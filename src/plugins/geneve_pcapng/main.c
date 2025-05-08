/*
 * geneve_pcapng.c - GENEVE packet capture plugin for VPP
 *
 * Captures GENEVE tunneled packets (IPv4/IPv6) to PCAPng files
 * with support for filtering based on GENEVE options.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vppinfra/atomics.h>
#include <vlib/unix/unix.h>
#include <vppinfra/random.h>

/* Define PCAPng format related constants */
#define PCAPNG_BLOCK_TYPE_SHB        0x0A0D0D0A  /* Section Header Block */
#define PCAPNG_BLOCK_TYPE_IDB        0x00000001  /* Interface Description Block */
#define PCAPNG_BLOCK_TYPE_EPB        0x00000006  /* Enhanced Packet Block */
#define PCAPNG_BLOCK_TYPE_SPB        0x00000003  /* Simple Packet Block */

/* Geneve-specific constants */
#define GENEVE_UDP_DST_PORT 6081
#define GENEVE_VERSION_SHIFT 6
#define GENEVE_VERSION_MASK 0xC0
#define GENEVE_OPT_LEN_SHIFT 1
#define GENEVE_OPT_LEN_MASK 0x3E

/* Forward declarations */
typedef struct geneve_pcapng_main_t geneve_pcapng_main_t;
typedef struct geneve_option_def_t geneve_option_def_t;
typedef struct geneve_capture_filter_t geneve_capture_filter_t;
typedef struct geneve_option_filter_t geneve_option_filter_t;
typedef struct geneve_output_t geneve_output_t;

/* 
 * Option data types for GENEVE options
 */
typedef enum {
  GENEVE_OPT_TYPE_RAW = 0,     /* Raw bytes */
  GENEVE_OPT_TYPE_IPV4,        /* IPv4 address */
  GENEVE_OPT_TYPE_IPV6,        /* IPv6 address */
  GENEVE_OPT_TYPE_UINT8,       /* 8-bit integer */
  GENEVE_OPT_TYPE_UINT16,       /* 16-bit integer */
  GENEVE_OPT_TYPE_UINT32,       /* 32-bit integer */
  GENEVE_OPT_TYPE_STRING,       /* String */
} geneve_opt_data_type_t;

/* Enhanced option definition for user-friendly filtering */
struct geneve_option_def_t {
  char *option_name;                   /* Friendly name for the option */
  u16 opt_class;                /* Class field */
  u8 type;                      /* Type field */
  u8 length;                    /* Length in bytes of the option data */
  geneve_opt_data_type_t preferred_type; /* Preferred input type for this option */
  format_function_t *format_fn; /* Optional format function for displaying option */
};


/* API declarations */
static clib_error_t *geneve_pcapng_init (vlib_main_t * vm);
void geneve_pcapng_register_option_def (const char *name, u16 class, u8 type, u8 length, geneve_opt_data_type_t preferred_type);
int geneve_pcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter);
int geneve_pcapng_del_filter (u32 sw_if_index, u32 filter_id);
int geneve_pcapng_enable_capture (u32 sw_if_index, u8 enable);

/* Geneve option filters */
struct geneve_option_filter_t {
    u8 present;            /* 1 if this option filter is active */
    
    /* Option can be specified by name or by direct class/type */
    union {
      char *option_name;   /* Reference to registered option by name */
      struct {
        u16 opt_class;     /* Option class */
        u8 type;           /* Option type */
      };
    };
    
    u8 match_any;          /* If 1, just match the presence of the option */
    u8 data_len;           /* Length of data to match (can be shorter than actual option) */
    u8 *data;              /* Data to match against option value */
    u8 *mask;              /* Optional mask for data matching (NULL = exact match) */
};

/* Filter structure with matching criteria */
struct geneve_capture_filter_t {
  u32 filter_id;           /* Unique filter identifier */
  
  /* Basic Geneve header filters */
  u8 ver_present;          /* 1 if version field should be matched */
  u8 ver;                  /* Version to match */
  
  u8 opt_len_present;      /* 1 if option length should be matched */
  u8 opt_len;              /* Option length to match */
  
  u8 proto_present;        /* 1 if protocol should be matched */
  u16 protocol;            /* Inner protocol to match */
  
  u8 vni_present;          /* 1 if VNI should be matched */
  u32 vni;                 /* VNI to match */
  
  geneve_option_filter_t *option_filters;       /* Vector of option filters */

  /* outer header 5-tuple filter with mask */
  u8 outer_filter_present;           /* 1 if outer header filter is active */
  u8 *outer_header_mask;             /* Vector of bytes to mask in outer header */
  u8 *outer_header_value;            /* Vector of bytes to match (after masking) */
  u16 outer_header_length;           /* Length of outer header to match */
  
  /* inner header 5-tuple filter with mask */
  u8 inner_filter_present;           /* 1 if inner header filter is active */
  u8 *inner_header_mask;             /* Vector of bytes to mask in inner header */
  u8 *inner_header_value;            /* Vector of bytes to match (after masking) */
  u16 inner_header_length;           /* Length of inner header to match */

};

/* Output interface definition for extensibility */
struct geneve_output_t {
  void *(*init) (u32 worker_index);
  void (*cleanup) (void *ctx);
  int (*write_pcapng_shb) (void *ctx);
  int (*write_pcapng_idb) (void *ctx, u32 if_index, const char *if_name);
  int (*write_pcapng_epb) (void *ctx, u32 if_index, u64 timestamp, 
                           u32 orig_len, void *packet_data, u32 packet_len);
  /* Can be extended with additional methods */
};

/* File-based output implementation */
typedef struct {
  FILE *file;
  char *filename;
} file_output_ctx_t;

/* Plugin state */
struct geneve_pcapng_main_t {
  /* API message ID base */
  u16 msg_id_base;

  /* Vector of registered option definitions */
  geneve_option_def_t *option_defs;
  
  /* Hash table: option_name -> index in option_defs */
  uword *option_by_name;
  
  /* Hash table: (class,type) -> index in option_defs */
  uword *option_by_class_type;

  /* Global filters (applied to all interfaces with capture enabled) */
  geneve_capture_filter_t *global_filters;
  
  /* Per-interface filter data */
  struct {
    u8 capture_enabled;              /* Whether capture is enabled on this interface */
    geneve_capture_filter_t *filters; /* Vector of active filters */
  } *per_interface;
  
  /* Current output implementation */
  geneve_output_t output;
  
  /* Per-worker output contexts */
  void **worker_output_ctx;
  
  /* Feature arc indices */
  u32 ip4_geneve_input_arc;
  u32 ip6_geneve_input_arc;
};

/* Global plugin state */
static geneve_pcapng_main_t geneve_pcapng_main;

/******************************************************************************
 * PCAPng file format utilities
 ******************************************************************************/

static void *
file_output_init (u32 worker_index)
{
  file_output_ctx_t *ctx;
  char filename[256];

  ctx = clib_mem_alloc_aligned (sizeof (file_output_ctx_t), CLIB_CACHE_LINE_BYTES);
  memset (ctx, 0, sizeof (*ctx));

  /* Create a unique filename per worker */
  snprintf (filename, sizeof (filename), "/tmp/geneve_capture_worker%u.pcapng", worker_index);
  ctx->filename = (void *)format (0, "%s%c", filename, 0);
  
  ctx->file = fopen ((char *) ctx->filename, "wb+");
  if (!ctx->file)
    {
      clib_warning ("Failed to create PCAPng file: %s", ctx->filename);
      vec_free (ctx->filename);
      clib_mem_free (ctx);
      return NULL;
    }
  else {
    clib_warning("File is open: %s. file handle: %p", ctx->filename, ctx->file);
  }
  
  return ctx;
}

static void
file_output_cleanup (void *context)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  
  if (!ctx)
    return;
    
  if (ctx->file) {
    clib_warning("closing the file");
    fclose (ctx->file);
  }
    
  vec_free (ctx->filename);
  clib_mem_free (ctx);
}

static int
file_write_pcapng_shb (void *context)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  struct {
    u32 block_type;
    u32 block_len;
    u32 magic;
    u16 major_version;
    u16 minor_version;
    u64 section_len;
    u32 block_len_copy;
  } __attribute__ ((packed)) shb;
  
  if (!ctx || !ctx->file)
    return -1;
    
  memset (&shb, 0, sizeof (shb));
  shb.block_type = PCAPNG_BLOCK_TYPE_SHB;
  shb.block_len = sizeof (shb);
  shb.magic = 0x1A2B3C4D;  /* Byte order magic */
  shb.major_version = 1;
  shb.minor_version = 0;
  shb.section_len = 0xFFFFFFFFFFFFFFFF;  /* Unknown length */
  shb.block_len_copy = sizeof (shb);
  
  return fwrite (&shb, 1, sizeof (shb), ctx->file) == sizeof (shb) ? 0 : -1;
}

static int
file_write_pcapng_idb (void *context, u32 if_index, const char *if_name)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  u32 name_len, pad_len, total_len;
  u8 *block;
  int result;
  
  if (!ctx || !ctx->file)
    return -1;
    
  /* Calculate the padded name length (must be 32-bit aligned) */
  name_len = strlen (if_name) + 1;  /* Include null terminator */
  pad_len = (4 - (name_len % 4)) % 4;
  
  /* Total length of the IDB block */
  total_len = 20 + name_len + pad_len + 4;
  
  block = clib_mem_alloc (total_len);
  if (!block)
    return -1;
  
  /* Fill in the IDB block */
  *(u32 *)(block) = PCAPNG_BLOCK_TYPE_IDB;
  *(u32 *)(block + 4) = total_len;
  *(u16 *)(block + 8) = 1;  /* Link type: LINKTYPE_ETHERNET */
  *(u16 *)(block + 10) = 0; /* Reserved */
  *(u32 *)(block + 12) = 0; /* SnapLen: no limit */
  *(u16 *)(block + 16) = 2; /* ifname */
  *(u16 *)(block + 18) = name_len; /* ifname len */
  
  /* Copy interface name to the options section */
  memcpy (block + 20, if_name, name_len - 1);
  block[20 + name_len - 1] = 0;  /* Ensure null termination */
  
  /* Add padding bytes */
  memset (block + 20 + name_len, 0, pad_len);
  
  /* Add block length at the end */
  *(u32 *)(block + total_len - 4) = total_len;
  
  /* Write the block to file */
  result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  
  clib_mem_free (block);
  return result;
}

static int
file_write_pcapng_epb (void *context, u32 if_index, u64 timestamp,
                       u32 orig_len, void *packet_data, u32 packet_len)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  u32 pad_len, total_len;
  u8 *block;
  int result;
  
  if (!ctx || !ctx->file)
    return -1;
    
  /* Calculate padding length (must be 32-bit aligned) */
  pad_len = (4 - (packet_len % 4)) % 4;
  
  /* Total length of the EPB block */
  total_len = 28 + packet_len + pad_len + 4;
  
  block = clib_mem_alloc (total_len);
  if (!block)
    return -1;
  
  /* Fill in the EPB block */
  *(u32 *)(block) = PCAPNG_BLOCK_TYPE_EPB;
  *(u32 *)(block + 4) = total_len;
  *(u32 *)(block + 8) = if_index;
  *(u32 *)(block + 12) = timestamp >> 32;  /* Timestamp (high) */
  *(u32 *)(block + 16) = timestamp & 0xFFFFFFFF;  /* Timestamp (low) */
  *(u32 *)(block + 20) = packet_len;  /* Captured length */
  *(u32 *)(block + 24) = orig_len;    /* Original length */
  
  /* Copy packet data */
  memcpy (block + 28, packet_data, packet_len);
  
  /* Add padding bytes */
  memset (block + 28 + packet_len, 0, pad_len);
  
  /* Add block length at the end */
  *(u32 *)(block + total_len - 4) = total_len;
  
  /* Write the block to file */
  result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  
  if (result == 0)
    fflush (ctx->file);  /* Ensure data is written to disk */
  
  clib_mem_free (block);
  return result;
}

/******************************************************************************
 * Packet processing and GENEVE parsing
 ******************************************************************************/

/* GENEVE header structure */
typedef struct {
  u8 ver_opt_len;      /* Version and option length */
  u8 flags;            /* Flags */
  u16 protocol;        /* Protocol type */
  u8 vni[3];           /* VNI (24 bits) */
  u8 reserved;         /* Reserved */
} geneve_header_t;

/* GENEVE option structure */
typedef struct {
  u16 opt_class;       /* Option class */
  u8 type;             /* Type */
  u8 flags_length;     /* Flags (4 bits) and length (4 bits) in 4-byte multiples */
  u8 data[0];          /* Option data (variable length) */
} geneve_option_t;

static_always_inline u8
geneve_get_version (const geneve_header_t *h)
{
  return (h->ver_opt_len & GENEVE_VERSION_MASK) >> GENEVE_VERSION_SHIFT;
}

static_always_inline u8
geneve_get_opt_len (const geneve_header_t *h)
{
  return (h->ver_opt_len & GENEVE_OPT_LEN_MASK) >> GENEVE_OPT_LEN_SHIFT;
}

static_always_inline u32
geneve_get_vni (const geneve_header_t *h)
{
  return (((u32) h->vni[0]) << 16) | (((u32) h->vni[1]) << 8) | h->vni[2];
}

static_always_inline u8
geneve_opt_get_length (const geneve_option_t *opt)
{
  return (opt->flags_length & 0x1F) * 4;
}

/* Check if packet matches a Geneve filter */
static bool
filter_matches_packet (geneve_pcapng_main_t *gpm,
                             const geneve_header_t *hdr,
                             u32 geneve_header_len,
                             const geneve_capture_filter_t *filter)
{
  const geneve_option_t *opt;
  u32 remaining_len;
  int i;

  /* Check basic header fields if specified in filter */
  if (filter->ver_present && filter->ver != geneve_get_version (hdr))
    return false;
    
  if (filter->opt_len_present && filter->opt_len != geneve_get_opt_len (hdr))
    return false;
    
  if (filter->proto_present && filter->protocol != clib_net_to_host_u16 (hdr->protocol))
    return false;
    
  if (filter->vni_present && filter->vni != geneve_get_vni (hdr))
    return false;

  /* Check outer header filter if present */
  if (filter->outer_filter_present)
  {
    const u8 *outer_header = (const u8 *)ether;
    u16 i;

    /* Make sure buffer has enough data */
    if (filter->outer_header_length > vlib_buffer_length_in_chain (gpm->vlib_main, buf0))
      return false;
    
    /* Perform masked comparison of outer header */
    for (i = 0; i < filter->outer_header_length; i++)
    {
      if ((outer_header[i] & filter->outer_header_mask[i]) != filter->outer_header_value[i])
        return false;
    }
  }

  /* Check inner header filter if present */
  if (filter->inner_filter_present)
  {
    /* Calculate pointer to inner header (after Geneve) */
    const u8 *inner_header = (const u8 *)geneve + sizeof(geneve_header_t) + 
                            geneve_get_opt_len(geneve) * 4;
    u16 i;
    
    /* Make sure buffer has enough data */
    u32 outer_header_len = (u8 *)inner_header - (u8 *)ether;
    if (outer_header_len + filter->inner_header_length > 
        vlib_buffer_length_in_chain (gpm->vlib_main, buf0))
      return false;
    
    /* Perform masked comparison of inner header */
    for (i = 0; i < filter->inner_header_length; i++)
    {
      if ((inner_header[i] & filter->inner_header_mask[i]) != filter->inner_header_value[i])
        return false;
    }
  }
  
    
  /* No option filters, match just on basic headers */
  if (vec_len (filter->option_filters) == 0)
    return true;

  /* Start of options */
  opt = (const geneve_option_t *)(hdr + 1);
  remaining_len = geneve_header_len - sizeof (geneve_header_t);
  
  /* Check each option filter */
  for (i = 0; i < vec_len (filter->option_filters); i++)
    {
      const geneve_option_t *current_opt = opt;
      bool found = false;
      u16 opt_class;
      u8 opt_type;
      uword *p;
      
      /* Resolve option class/type from name if needed */
      if (filter->option_filters[i].option_name)
        {
          /* Look up option definition by name */
          p = hash_get_mem (gpm->option_by_name, filter->option_filters[i].option_name);
          if (!p)
            return false;  /* Unknown option name, can't match */
            
          const geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
          opt_class = opt_def->opt_class;
          opt_type = opt_def->type;
        }
      else
        {
          /* Use direct option class/type from filter */
          opt_class = filter->option_filters[i].opt_class;
          opt_type = filter->option_filters[i].type;
        }
      
      /* Search for the option in the packet */
      current_opt = opt;
      while (remaining_len >= sizeof (geneve_option_t))
        {
          u8 opt_len = geneve_opt_get_length (current_opt);
          
          /* Check if this option matches what we're looking for */
          if (clib_net_to_host_u16 (current_opt->opt_class) == opt_class &&
              current_opt->type == opt_type)
            {
              found = true;
              
              /* If we only care about presence, we're done */
              if (filter->option_filters[i].match_any)
                break;
                
              /* Check data content */
              if (filter->option_filters[i].data_len > 0)
                {
                  u8 check_len = filter->option_filters[i].data_len;
                  
                  /* Make sure we don't try to match more than the actual option data */
                  if (check_len > opt_len - 4) 
                    check_len = opt_len - 4;
                    
                  /* Skip matching if not enough data */
                  if (check_len <= 0)
                    {
                      found = false;
                      break;
                    }
                  
                  /* If we have a mask, apply it */
                  if (filter->option_filters[i].mask)
                    {
                      u8 j;
                      for (j = 0; j < check_len; j++)
                        {
                          u8 masked_data = current_opt->data[j] & filter->option_filters[i].mask[j];
                          u8 masked_filter = filter->option_filters[i].data[j] & filter->option_filters[i].mask[j];
                          
                          if (masked_data != masked_filter)
                            {
                              found = false;
                              break;
                            }
                        }
                    }
                  else
                    {
                      /* Exact match */
                      if (memcmp (current_opt->data, filter->option_filters[i].data, check_len) != 0)
                        found = false;
                    }
                }
                
              break;
            }
            
          /* Move to next option */
          if (opt_len < sizeof (geneve_option_t))
            break;  /* Malformed option */
            
          current_opt = (const geneve_option_t *)((u8 *)current_opt + opt_len);
          remaining_len -= opt_len;
        }
        
      /* If required option wasn't found, no match */
      if (!found)
        return false;
    }
    
  /* All filters matched */
  return true;
}

static bool
geneve_packet_matches_filter (geneve_pcapng_main_t *gpm,
                             const geneve_header_t *hdr,
                             u32 geneve_header_len,
                             u32 sw_if_index)
{
  int i;
  
  /* Check interface-specific filters first (if any) */
  if (sw_if_index < vec_len(gpm->per_interface) && 
      gpm->per_interface[sw_if_index].filters != NULL)
  {
    for (i = 0; i < vec_len(gpm->per_interface[sw_if_index].filters); i++)
    {
      if (filter_matches_packet(gpm, hdr, geneve_header_len, 
                              &gpm->per_interface[sw_if_index].filters[i]))
        return true;
    }
  }
  
  /* Then check global filters */
  for (i = 0; i < vec_len(gpm->global_filters); i++)
  {
    if (filter_matches_packet(gpm, hdr, geneve_header_len, 
                             &gpm->global_filters[i]))
      return true;
  }
  
  return false;
}

/* Filter and capture Geneve packets */
VLIB_NODE_FN (geneve_pcapng_node) (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u32 n_left_from, *from, *to_next;
  u32 n_left_to_next;
  u32 worker_index = vlib_get_thread_index ();
  void *output_ctx;
  u32 next_index;
  int i;
  
  /* Get output context for this worker */
  output_ctx = gpm->worker_output_ctx[worker_index];
  if (!output_ctx)
    {
      /* Initialize the output context if not already done */
      output_ctx = gpm->output.init (worker_index);
      if (!output_ctx)
        {
          /* Failed to initialize output */
          return frame->n_vectors;
        }
        
      /* Write PCAPng header */
      gpm->output.write_pcapng_shb (output_ctx);
      static u8 *if_name = 0;
      int i;
      // FIXME: retrieve the real interfaces
      for (i=0; i<5; i++) {
        vec_reset_length (if_name);
        if_name = format (if_name, "vpp-if-%d%c", i, 0);
        gpm->output.write_pcapng_idb (output_ctx, i, (char *)if_name);
      }
      
      /* Store the context */
      gpm->worker_output_ctx[worker_index] = output_ctx;
    }
  
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t *b0;
          u32 bi0, sw_if_index0, next0 = 0;
          ip4_header_t *ip4;
          ip6_header_t *ip6;
          ethernet_header_t *ether;
          udp_header_t *udp;
          geneve_header_t *geneve;
          // bool is_ip6;
          // bool packet_captured = false;
          
          /* Prefetch next packet */
          if (n_left_from > 1)
            {
              vlib_buffer_t *b1;
              b1 = vlib_get_buffer (vm, from[1]);
              CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);
            }
          
          /* Get current packet */
          bi0 = from[0];
          from += 1;
          n_left_from -= 1;
          to_next[0] = bi0;
          to_next += 1;
          n_left_to_next -= 1;
          
          b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vnet_feature_next (&next0, b0);
          
          /* Skip interfaces where capture is not enabled */
          if (sw_if_index0 >= vec_len (gpm->per_interface) ||
              !gpm->per_interface[sw_if_index0].capture_enabled)
            {
              goto packet_done;
            }
          
          /* Parse either IPv4 or IPv6 header */
          ether = vlib_buffer_get_current (b0);
          ip4 = (ip4_header_t *) (ether+1);
          if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
            {
              /* IPv4 */
              // is_ip6 = false;
              
              /* Skip non-UDP packets */
              if (ip4->protocol != IP_PROTOCOL_UDP)
                goto packet_done;
                
              /* UDP header follows IPv4 header */
              udp = (udp_header_t *)(ip4 + 1);
            }
          else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60)
            {
              /* IPv6 */
              // is_ip6 = true;
              ip6 = (ip6_header_t *)ip4;
              
              /* Skip non-UDP packets */
              if (ip6->protocol != IP_PROTOCOL_UDP)
                goto packet_done;
                
              /* UDP header follows IPv6 header */
              udp = (udp_header_t *)(ip6 + 1);
            }
          else
            {
              /* Neither IPv4 nor IPv6 */
              goto packet_done;
            }
          
          /* Check UDP port for GENEVE */
          if (clib_net_to_host_u16 (udp->dst_port) != GENEVE_UDP_DST_PORT)
            goto packet_done;
            
          /* GENEVE header follows UDP header */
          geneve = (geneve_header_t *)(udp + 1);
          
          /* Calculate GENEVE header length including options */
          u32 geneve_opt_len = geneve_get_opt_len (geneve) * 4;
          u32 geneve_header_len = sizeof (geneve_header_t) + geneve_opt_len;
          
          /* Check if the packet matches any filter */
          for (i = 0; i < vec_len (gpm->per_interface[sw_if_index0].filters); i++)
            {
              if (geneve_packet_matches_filter (gpm, geneve, geneve_header_len,
                                              &gpm->per_interface[sw_if_index0].filters[i]))
                {
                  /* Packet matches, capture it */
                  u64 timestamp = vlib_time_now (vm) * 1000000000; /* ns */
                  u32 orig_len = vlib_buffer_length_in_chain (vm, b0);
                  vlib_buffer_t *buf_iter = b0;
                  
                  /* Add interface description to PCAPng file if needed */
                  static u8 *if_name = 0;
                  vec_reset_length (if_name);
                  if_name = format (if_name, "vpp-if-%d%c", sw_if_index0, 0);
                  
                 // gpm->output.write_pcapng_idb (output_ctx, sw_if_index0, (char *)if_name);
                  
                  /* Allocate a temporary buffer for the entire packet */
                  u8 *packet_copy = 0;
                  vec_validate (packet_copy, orig_len - 1);
                  
                  /* Copy packet data from buffer chain */
                  u32 offset = 0;
                  while (buf_iter)
                    {
                      u32 len = buf_iter->current_length;
                      clib_memcpy_fast (packet_copy + offset, 
                                         vlib_buffer_get_current (buf_iter),
                                         len);
                      offset += len;
                      buf_iter = buf_iter->flags & VLIB_BUFFER_NEXT_PRESENT ?
                                vlib_get_buffer (vm, buf_iter->next_buffer) : 0;
                    }
                  
                  /* Write packet data to PCAPng file */
                  gpm->output.write_pcapng_epb (output_ctx, sw_if_index0, 
                                               timestamp, orig_len, 
                                               packet_copy, offset);
                                               
                  vec_free (packet_copy);
                  // packet_captured = true;
                  break;
                }
            }
          
packet_done:
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }
        
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    
  return frame->n_vectors;
}

/* Node registration */
vlib_node_registration_t geneve_pcapng_node;

VLIB_REGISTER_NODE (geneve_pcapng_node) = {
  .name = "geneve-pcapng-capture",
  .vector_size = sizeof (u32),
  .format_trace = 0,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  // Specify next nodes if any
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VNET_FEATURE_INIT (geneve_pcapng_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "geneve-pcapng-capture",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};


/******************************************************************************
 * API and initialization
 ******************************************************************************/

static u32 random_seed = 42;

int
geneve_pcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  geneve_capture_filter_t *new_filter;
  u32 filter_id;
  
  /* Validate sw_if_index */
  if (sw_if_index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    
  /* Ensure we have space for this interface */
  vec_validate (gpm->per_interface, sw_if_index);
  
  /* Generate a unique filter ID */
  filter_id = random_u32(&random_seed);
  
  /* Add the filter */
  vec_add2 (gpm->per_interface[sw_if_index].filters, new_filter, 1);
  
  /* Copy filter data */
  clib_memcpy (new_filter, filter, sizeof (geneve_capture_filter_t));
  new_filter->filter_id = filter_id;
  
  /* Handle option filters */
  if (filter->option_filters)
    {
      int i;
      
      /* Allocate and copy option filters vector */
      vec_validate (new_filter->option_filters, 
                    vec_len (filter->option_filters) - 1);
                    
      for (i = 0; i < vec_len (filter->option_filters); i++)
        {
          clib_memcpy (&new_filter->option_filters[i],
                       &filter->option_filters[i],
                       sizeof (filter->option_filters[i]));
                       
          /* Copy option name if present */
          if (filter->option_filters[i].option_name)
            {
              new_filter->option_filters[i].option_name = 
                vec_dup (filter->option_filters[i].option_name);
            }
            
          /* Copy data and mask if present */
          if (filter->option_filters[i].data)
            {
              new_filter->option_filters[i].data = 
                vec_dup_aligned (filter->option_filters[i].data,
                   //              filter->option_filters[i].data_len,
                                 CLIB_CACHE_LINE_BYTES);
            }
            
          if (filter->option_filters[i].mask)
            {
              new_filter->option_filters[i].mask = 
                vec_dup_aligned (filter->option_filters[i].mask,
                    //             filter->option_filters[i].data_len,
                                 CLIB_CACHE_LINE_BYTES);
            }
        }
    }
    
  return filter_id;
}


int
geneve_pcapng_enable_capture (u32 sw_if_index, u8 enable)
{
  geneve_pcapng_main_t *gmp = &geneve_pcapng_main;
  vnet_main_t *vnm = vnet_get_main ();
  // vnet_feature_config_main_t *cm;
  // vnet_config_main_t *vcm;
  // u8 feature_index;

  /* Validate interface index */
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Ensure we have storage for this interface */
  vec_validate (gmp->per_interface, sw_if_index);

  /* Update the enabled state */
  gmp->per_interface[sw_if_index].capture_enabled = enable;

  /* Get the feature config for interface-output feature arc */
  // cm = &vnm->vnet_features[VNET_MAIN_THREAD /* or vnet_worker_thread_barrier_async (m) */].interface_output_feature_config;
  // vcm = &cm->config_main;

  /* Get the feature index for our capture node */
  // feature_index = vnet_feature_get_config_index_by_node_name (vnm, "interface-output", "geneve-pcapng-capture");

  if (enable)
    {
      /* Enable the feature on this interface */
      vnet_feature_enable_disable ("interface-output", "geneve-pcapng-capture",
                                   sw_if_index, 1, 0, 0);
    }
  else
    {
      /* Disable the feature on this interface */
      vnet_feature_enable_disable ("interface-output", "geneve-pcapng-capture",
                                   sw_if_index, 0, 0, 0);

      /* Clean up any resources for this interface */
      if (vec_len (gmp->per_interface[sw_if_index].filters) > 0)
        {
          /* Optionally: Clear all filters when disabling capture */
          /* vec_free (gmp->per_interface[sw_if_index].filters); */
        }
    }

  return 0;
}

static clib_error_t *
geneve_pcapng_enable_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index = ~0;
  u8 enable = 1;
  
  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");
    
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U",
                   unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else if (unformat (line_input, "disable"))
        enable = 0;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }
    
  /* Validate inputs */
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface required");
      goto done;
    }
    
  /* Enable/disable capture */
  int rv = geneve_pcapng_enable_capture (sw_if_index, enable);
  if (rv)
    {
      error = clib_error_return (0, "failed to %s capture on interface %d: error %d",
                                enable ? "enable" : "disable", sw_if_index, rv);
      goto done;
    }
    
  vlib_cli_output (vm, "GENEVE packet capture %s on interface %d",
                  enable ? "enabled" : "disabled", sw_if_index);
  
done:
  unformat_free (line_input);
  return error;
}

/* Register with preferred data type */
void
geneve_pcapng_register_option_def (const char *name, u16 class, u8 type, u8 length,
                                  geneve_opt_data_type_t preferred_type)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  geneve_option_def_t opt_def = {0};
  u64 key;
  u32 index;
  
  /* Create option definition */
  opt_def.option_name = (void *)format (0, "%s%c", name, 0);
  opt_def.opt_class = class;
  opt_def.type = type;
  opt_def.length = length;
  opt_def.preferred_type = preferred_type;
  
  /* Add to vector */
  index = vec_len (gpm->option_defs);
  vec_add1 (gpm->option_defs, opt_def);
  
  /* Add to hash tables */
  hash_set_mem (gpm->option_by_name, opt_def.option_name, index);
  
  key = ((u64)class << 8) | type;
  hash_set (gpm->option_by_class_type, key, index);
}

/* 
 * Helper function to parse option data based on type
 */
static clib_error_t *
parse_option_data (unformat_input_t * input, geneve_opt_data_type_t type,
                  u8 **data, u8 data_len)
{
  ip4_address_t ip4;
  ip6_address_t ip6;
  u32 value32;
  u16 value16;
  u8 value8;
  u8 *s = 0;
  u8 *raw_data = 0;
  u8 byte_val;
  int i;
  
  switch (type)
    {
    case GENEVE_OPT_TYPE_IPV4:
      if (unformat (input, "%U", unformat_ip4_address, &ip4))
        {
          *data = vec_new (u8, 4);
          clib_memcpy (*data, &ip4, 4);
          return 0;
        }
      return clib_error_return (0, "invalid IPv4 address format");
      
    case GENEVE_OPT_TYPE_IPV6:
      if (unformat (input, "%U", unformat_ip6_address, &ip6))
        {
          *data = vec_new (u8, 16);
          clib_memcpy (*data, &ip6, 16);
          return 0;
        }
      return clib_error_return (0, "invalid IPv6 address format");
      
    case GENEVE_OPT_TYPE_UINT8:
      if (unformat (input, "%u", &value32) && value32 <= 255)
        {
          value8 = (u8)value32;
          *data = vec_new (u8, 1);
          clib_memcpy (*data, &value8, 1);
          return 0;
        }
      return clib_error_return (0, "invalid 8-bit integer format");
      
    case GENEVE_OPT_TYPE_UINT16:
      if (unformat (input, "%u", &value32) && value32 <= 65535)
        {
          value16 = (u16)value32;
          value16 = clib_host_to_net_u16 (value16);
          *data = vec_new (u8, 2);
          clib_memcpy (*data, &value16, 2);
          return 0;
        }
      return clib_error_return (0, "invalid 16-bit integer format");
      
    case GENEVE_OPT_TYPE_UINT32:
      if (unformat (input, "%u", &value32))
        {
          value32 = clib_host_to_net_u32 (value32);
          *data = vec_new (u8, 4);
          clib_memcpy (*data, &value32, 4);
          return 0;
        }
      return clib_error_return (0, "invalid 32-bit integer format");
      
    case GENEVE_OPT_TYPE_STRING:
      if (unformat (input, "%v", &s))
        {
          /* Limit string to data_len - 1 (for NULL terminator) */
          if (vec_len (s) > data_len - 1)
            vec_set_len (s, data_len - 1);
          
          /* Allocate data vector and copy string with NULL terminator */
          *data = vec_new (u8, data_len);
          clib_memset (*data, 0, data_len);
          clib_memcpy (*data, s, vec_len (s));
          vec_free (s);
          return 0;
        }
      return clib_error_return (0, "invalid string format");
      
    case GENEVE_OPT_TYPE_RAW:
      /* Format: "HH HH HH ..." where HH is a hex byte */
      raw_data = vec_new (u8, data_len);
      clib_memset (raw_data, 0, data_len);
      
      for (i = 0; i < data_len; i++)
        {
          if (!unformat (input, "%x", &byte_val))
            {
              vec_free (raw_data);
              return clib_error_return (0, 
                "invalid raw format, expected %d hex bytes", data_len);
            }
          raw_data[i] = byte_val;
        }
      *data = raw_data;
      return 0;
      
    default:
      return clib_error_return (0, "unsupported option data type");
    }
}

/* Parse a hex string into a vector of bytes */
uword
unformat_hex_string (unformat_input_t * input, va_list * args)
{
  u8 **hexstring = va_arg (*args, u8 **);
  u8 *s = 0;
  u8 *result = 0;
  uword length = 0;
  
  if (!unformat (input, "%s", &s))
    return 0;
    
  /* Convert string of format "AABB CCDD EEFF" to byte array */
  result = parse_hex_string ((char *)s);
  vec_free (s);
  
  if (!result)
    return 0;
    
  length = vec_len (result);
  *hexstring = result;
  
  return 1;
}

/* Parse IP address and mask for 5-tuple filter */
uword
unformat_ip4_address_and_mask (unformat_input_t * input, va_list * args)
{
  u8 **mask = va_arg (*args, u8 **);
  u8 **value = va_arg (*args, u8 **);
  u16 *offset = va_arg (*args, u16 *);
  ip4_address_t ip_addr, ip_mask;
  
  /* Default to exact match if no mask specified */
  if (unformat (input, "%U/%U", unformat_ip4_address, &ip_addr, 
                             unformat_ip4_address, &ip_mask))
    {
      /* Got IP and mask */
    }
  else if (unformat (input, "%U", unformat_ip4_address, &ip_addr))
    {
      /* Just got IP, set mask to all ones for exact match */
      memset (&ip_mask, 0xFF, sizeof (ip_mask));
    }
  else
    return 0;
    
  /* 
   * Now add the IP address and mask to the correct offset in the 
   * filter mask and value vectors.
   * This requires knowledge of the header structure and offsets.
   */
  
  /* Ensure vectors are large enough */
  ensure_filter_size (mask, value, IP4_OFFSET + sizeof (ip4_address_t));
  
  /* Add IP address to value */
  clib_memcpy (*value + IP4_OFFSET, &ip_addr, sizeof (ip4_address_t));
  
  /* Add mask to mask */
  clib_memcpy (*mask + IP4_OFFSET, &ip_mask, sizeof (ip4_address_t));
  
  return 1;
}

/* Helper function to ensure filter vectors are big enough */
static void
ensure_filter_size (u8 **mask, u8 **value, u16 required_size)
{
  /* Create vectors if they don't exist */
  if (*mask == NULL)
    *mask = vec_new (u8, required_size);
  else if (vec_len (*mask) < required_size)
    vec_validate (*mask, required_size - 1);
    
  if (*value == NULL)
    *value = vec_new (u8, required_size);
  else if (vec_len (*value) < required_size)
    vec_validate (*value, required_size - 1);
    
  /* Initialize to zeros for any new elements */
  memset (*mask + vec_len (*mask) - (required_size - vec_len (*mask)), 0, 
         required_size - vec_len (*mask));
  memset (*value + vec_len (*value) - (required_size - vec_len (*value)), 0, 
         required_size - vec_len (*value));
}

/* Get the offset of source port based on the protocol */
static u16
get_src_port_offset (u8 **mask)
{
  /* This is a simplified example - real implementation would determine
   * the offset based on examining the mask to identify protocol
   */
  if (is_ipv4_filter (*mask))
    return IPV4_HEADER_SIZE + 0; /* Offset of src port in UDP/TCP header */
  else if (is_ipv6_filter (*mask))
    return IPV6_HEADER_SIZE + 0; /* Offset of src port in UDP/TCP header */
  
  /* Default offset for unknown protocols */
  return 0;
}

/* Add a port value to the filter at specific offset */
static void
add_port_to_filter (u8 **mask, u8 **value, u16 port, u16 offset)
{
  u16 port_network_order = clib_host_to_net_u16 (port);
  
  /* Ensure vectors are large enough */
  ensure_filter_size (mask, value, offset + sizeof (u16));
  
  /* Set port in value */
  clib_memcpy (*value + offset, &port_network_order, sizeof (u16));
  
  /* Set mask (all bits set for exact match) */
  memset (*mask + offset, 0xFF, sizeof (u16));
}

/* Determine if the filter appears to be for IPv4 */
static bool
is_ipv4_filter (u8 *mask)
{
  /* Look for IPv4 version (4) in high nibble of first byte */
  if (vec_len (mask) >= 1 && (mask[0] & 0xF0) == 0x40)
    return true;
    
  return false;
}

static u8 *
format_header_filter (u8 *s, va_list *args)
{
  u8 *mask = va_arg (*args, u8 *);
  u8 *value = va_arg (*args, u8 *);
  u16 length = va_arg (*args, u16);
  u8 is_inner = va_arg (*args, int); /* promoted to int */
  u16 i;
  
  s = format (s, "  %s Header Filter (%u bytes):\n", 
             is_inner ? "Inner" : "Outer", length);
  
  /* Try to interpret as 5-tuple if possible */
  if (try_format_as_5tuple (s, mask, value, length, is_inner))
    return s;
    
  /* Otherwise format as raw hex */
  s = format (s, "    Mask:  ");
  for (i = 0; i < length; i++)
    {
      s = format (s, "%02x", mask[i]);
      if ((i + 1) % 16 == 0 && i < length - 1)
        s = format (s, "\n           ");
      else if ((i + 1) % 4 == 0 && i < length - 1)
        s = format (s, " ");
    }
    
  s = format (s, "\n    Value: ");
  for (i = 0; i < length; i++)
    {
      s = format (s, "%02x", value[i]);
      if ((i + 1) % 16 == 0 && i < length - 1)
        s = format (s, "\n           ");
      else if ((i + 1) % 4 == 0 && i < length - 1)
        s = format (s, " ");
    }
    
  return s;
}

static bool
try_format_as_5tuple (u8 *s, u8 *mask, u8 *value, u16 length, u8 is_inner)
{
  /* Try to identify IP version */
  if (length < 20)
    return false; /* Too short for IPv4 */
    
  /* Check IP version in first byte */
  if ((value[0] & 0xF0) == 0x40)
    {
      /* Looks like IPv4 */
      ip4_address_t src_ip, dst_ip;
      u16 src_port, dst_port;
      u8 protocol;
      
      /* Extract fields based on IPv4 header layout */
      protocol = value[9];
      clib_memcpy (&src_ip, value + 12, sizeof (src_ip));
      clib_memcpy (&dst_ip, value + 16, sizeof (dst_ip));
      
      /* Extract ports based on protocol */
      if (protocol == IP_PROTOCOL_UDP || protocol == IP_PROTOCOL_TCP)
        {
          if (length >= 24)
            {
              clib_memcpy (&src_port, value + 20, sizeof (src_port));
              clib_memcpy (&dst_port, value + 22, sizeof (dst_port));
              
              /* Format as 5-tuple */
              s = format (s, "    IPv4 5-tuple: proto=%d, src=%U:%d, dst=%U:%d\n",
                         protocol,
                         format_ip4_address, &src_ip, clib_net_to_host_u16 (src_port),
                         format_ip4_address, &dst_ip, clib_net_to_host_u16 (dst_port));
              return true;
            }
        }
        
      /* Format as 3-tuple */
      s = format (s, "    IPv4 3-tuple: proto=%d, src=%U, dst=%U\n",
                 protocol,
                 format_ip4_address, &src_ip,
                 format_ip4_address, &dst_ip);
      return true;
    }
  else if ((value[0] & 0xF0) == 0x60)
    {
      /* FIXME: Looks like IPv6 - similarly extract and format */
      /* ... */
    }
    
  return false; /* Not recognized as 5-tuple */
}



static clib_error_t *
geneve_pcapng_filter_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  clib_error_t *error = NULL;
  geneve_capture_filter_t filter = {0};
  u32 sw_if_index = ~0;
  u8 is_add = 1;
  u32 filter_id = ~0;
  char * option_name = 0;

  /* Current filter being defined (outer or inner) */
  u8 **current_mask = NULL;
  u8 **current_value = NULL;
  u16 *current_length = NULL;
  u8 *current_present = NULL;
  
  
  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");
    
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U",
                   unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "id %d", &filter_id))
        ;
      else if (unformat (line_input, "ver %d", &filter.ver))
        filter.ver_present = 1;
      else if (unformat (line_input, "opt-len %d", &filter.opt_len))
        filter.opt_len_present = 1;
      else if (unformat (line_input, "protocol %d", &filter.protocol))
        filter.proto_present = 1;
      else if (unformat (line_input, "vni %d", &filter.vni))
        filter.vni_present = 1;
      else if (unformat (line_input, "option %s", &option_name))
        {
          /* Create option filter */
          geneve_option_filter_t opt_filter = {0};
          
          uword *p;
          
          /* Look up the option by name */
          p = hash_get_mem (gpm->option_by_name, option_name);
          if (!p)
            {
              error = clib_error_return (0, "unknown option name: %s",
                                        option_name);
              goto done;
            }
            
          const geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
          opt_filter.present = 1;
          opt_filter.option_name = vec_dup (option_name);
          
          /* Check if next token is "any" */
          if (unformat (line_input, "any"))
            {
              opt_filter.match_any = 1;
            }
          else if (unformat (line_input, "value"))
            {
              geneve_opt_data_type_t data_type = opt_def->preferred_type;
              
              /* Check for explicit type specification */
              if (unformat (line_input, "raw"))
                data_type = GENEVE_OPT_TYPE_RAW;
              else if (unformat (line_input, "ipv4"))
                data_type = GENEVE_OPT_TYPE_IPV4;
              else if (unformat (line_input, "ipv6"))
                data_type = GENEVE_OPT_TYPE_IPV6;
              else if (unformat (line_input, "uint8"))
                data_type = GENEVE_OPT_TYPE_UINT8;
              else if (unformat (line_input, "uint16"))
                data_type = GENEVE_OPT_TYPE_UINT16;
              else if (unformat (line_input, "uint32"))
                data_type = GENEVE_OPT_TYPE_UINT32;
              else if (unformat (line_input, "string"))
                data_type = GENEVE_OPT_TYPE_STRING;
                
              /* Parse the option data based on type */
              opt_filter.data_len = opt_def->length;
              error = parse_option_data (line_input, data_type, 
                                        &opt_filter.data, opt_filter.data_len);
              if (error)
                goto done;
                
              /* Check for mask */
              if (unformat (line_input, "mask"))
                {
                  error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
                                           &opt_filter.mask, opt_filter.data_len);
                  if (error)
                    goto done;
                }
            }
          else
            {
              /* Default to match any if no value provided */
              opt_filter.match_any = 1;
            }
            
          /* Add the option filter to the vector */
          vec_add1 (filter.option_filters, opt_filter);
        }
      else if (unformat (line_input, "option-direct class %d type %d", 
                        &filter.option_filters->opt_class, 
                        &filter.option_filters->type))
        {
          /* Direct specification of option class/type */
          geneve_option_filter_t opt_filter = {0};
          
          u64 key;
          uword *p;
          
          opt_filter.present = 1;
          opt_filter.opt_class = filter.option_filters->opt_class;
          opt_filter.type = filter.option_filters->type;
          
          /* Try to find registered option info */
          key = ((u64)opt_filter.opt_class << 8) | opt_filter.type;
          p = hash_get (gpm->option_by_class_type, key);
          
          if (p)
            {
              /* Option is registered */
              const geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
              
              /* Check if next token is "any" */
              if (unformat (line_input, "any"))
                {
                  opt_filter.match_any = 1;
                }
              else if (unformat (line_input, "value"))
                {
                  geneve_opt_data_type_t data_type = opt_def->preferred_type;
                  
                  /* Check for explicit type specification */
                  if (unformat (line_input, "raw"))
                    data_type = GENEVE_OPT_TYPE_RAW;
                  else if (unformat (line_input, "ipv4"))
                    data_type = GENEVE_OPT_TYPE_IPV4;
                  else if (unformat (line_input, "ipv6"))
                    data_type = GENEVE_OPT_TYPE_IPV6;
                  else if (unformat (line_input, "uint8"))
                    data_type = GENEVE_OPT_TYPE_UINT8;
                  else if (unformat (line_input, "uint16"))
                    data_type = GENEVE_OPT_TYPE_UINT16;
                  else if (unformat (line_input, "uint32"))
                    data_type = GENEVE_OPT_TYPE_UINT32;
                  else if (unformat (line_input, "string"))
                    data_type = GENEVE_OPT_TYPE_STRING;
                    
                  /* Parse the option data based on type */
                  opt_filter.data_len = opt_def->length;
                  error = parse_option_data (line_input, data_type, 
                                            &opt_filter.data, opt_filter.data_len);
                  if (error)
                    goto done;
                    
                  /* Check for mask */
                  if (unformat (line_input, "mask"))
                    {
                      error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
                                              &opt_filter.mask, opt_filter.data_len);
                      if (error)
                        goto done;
                    }
                }
              else
                {
                  /* Default to match any if no value provided */
                  opt_filter.match_any = 1;
                }
            }
            
          /* Add the option filter to the vector */
          vec_add1 (filter.option_filters, opt_filter);
        }
/* New outer header filter */
      else if (unformat (line_input, "outer-header"))
        {
          /* Set current pointers to outer header filter */
          current_mask = &filter.outer_header_mask;
          current_value = &filter.outer_header_value;
          current_length = &filter.outer_header_length;
          current_present = &filter.outer_filter_present;
          *current_present = 1;
        }
      /* New inner header filter */
      else if (unformat (line_input, "inner-header"))
        {
          /* Set current pointers to inner header filter */
          current_mask = &filter.inner_header_mask;
          current_value = &filter.inner_header_value;
          current_length = &filter.inner_header_length;
          current_present = &filter.inner_filter_present;
          *current_present = 1;
        }
      /* Process hex input for mask/value pairs */
      else if (current_mask != NULL && unformat (line_input, "hex-mask %U", 
                                              unformat_hex_string, current_mask))
        {
          *current_length = vec_len(*current_mask);
        }
      else if (current_value != NULL && unformat (line_input, "hex-value %U", 
                                               unformat_hex_string, current_value))
        {
          /* Ensure mask and value have same length */
          if (*current_mask && vec_len(*current_mask) != vec_len(*current_value))
            {
              error = clib_error_return (0, "mask and value must have same length");
              goto done;
            }
          
          *current_length = vec_len(*current_value);
        }
      /* User-friendly 5-tuple specification for outer header */
      else if (current_mask != NULL && unformat (line_input, "src-ip %U", 
                                              unformat_ip4_address_and_mask, 
                                              current_mask, current_value, 
                                              current_length))
        {
          /* FIXME: Function would parse IP and mask, update the vectorsi; FIXME: IPv6 support ? */
        }
      else if (current_mask != NULL && unformat (line_input, "dst-ip %U", 
                                              unformat_ip4_address_and_mask, 
                                              current_mask, current_value, 
                                              current_length))
        {
          /* FIXME: Similar to src-ip; FIXME: IPv6 support ? */
        }
      else if (current_mask != NULL && unformat (line_input, "src-port %d", &src_port))
        {
          /* Add src port to mask/value at correct offset */
          add_port_to_filter(current_mask, current_value, src_port, 
                           get_src_port_offset(current_mask));
        }
      else if (current_mask != NULL && unformat (line_input, "dst-port %d", &dst_port))
        {
          /* Add dst port to mask/value at correct offset */
          add_port_to_filter(current_mask, current_value, dst_port, 
                           get_dst_port_offset(current_mask));
        }
      else if (current_mask != NULL && unformat (line_input, "proto %d", &proto))
        {
          /* Add protocol to mask/value at correct offset */
          add_proto_to_filter(current_mask, current_value, proto, 
                            get_proto_offset(current_mask));
        }
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }
    
  /* Validate inputs */
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface required");
      goto done;
    }
    
  if (!is_add && filter_id == ~0)
    {
      error = clib_error_return (0, "filter id required for delete");
      goto done;
    }
    
  /* Add/delete filter */
  if (is_add)
    {
      filter_id = geneve_pcapng_add_filter (sw_if_index, &filter);
      if (filter_id < 0)
        {
          error = clib_error_return (0, "failed to add filter");
          goto done;
        }
        
      vlib_cli_output (vm, "Added GENEVE filter with ID: %d", filter_id);
    }
  else
    {
      int rv = geneve_pcapng_del_filter (sw_if_index, filter_id);
      if (rv < 0)
        {
          error = clib_error_return (0, "failed to delete filter (id: %d)", filter_id);
          goto done;
        }
        
      vlib_cli_output (vm, "Deleted GENEVE filter with ID: %d", filter_id);
    }
    
done:
  unformat_free (line_input);
  return error;
}

/* Updated CLI command for better help text */
VLIB_CLI_COMMAND (geneve_pcapng_filter_command, static) = {
  .path = "geneve pcapng filter",
  .short_help = "geneve pcapng filter interface <interface> [ver <ver>] [opt-len <len>] [protocol <proto>] [vni <vni>] "
                "[option <name> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]] "
                "[option-direct class <class> type <type> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]] "
                "[del id <id>]",
  .function = geneve_pcapng_filter_command_fn,
};

/* Updated option registrations with preferred types */
static void
register_default_options (void)
{
  /* Register some basic GENEVE option definitions with preferred types */
  geneve_pcapng_register_option_def ("vpp-metadata", 0x0123, 0x01, 8, GENEVE_OPT_TYPE_UINT32);
  geneve_pcapng_register_option_def ("legacy-oam", 0x0F0F, 0x01, 4, GENEVE_OPT_TYPE_UINT32);
  geneve_pcapng_register_option_def ("tenant-ip", 0x0124, 0x02, 4, GENEVE_OPT_TYPE_IPV4);
  geneve_pcapng_register_option_def ("tenant-ipv6", 0x0124, 0x03, 16, GENEVE_OPT_TYPE_IPV6);
  geneve_pcapng_register_option_def ("flow-id", 0x0125, 0x01, 4, GENEVE_OPT_TYPE_UINT32);
  geneve_pcapng_register_option_def ("app-id", 0x0125, 0x02, 2, GENEVE_OPT_TYPE_UINT16);
  geneve_pcapng_register_option_def ("service-tag", 0x0126, 0x01, 8, GENEVE_OPT_TYPE_STRING);
}

static clib_error_t *
geneve_pcapng_register_option_command_fn (vlib_main_t * vm,
                                         unformat_input_t * input,
                                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u32 opt_class = 0;
  u32 type = 0;
  u32 length = 0;
  geneve_opt_data_type_t data_type = GENEVE_OPT_TYPE_RAW;

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &name))
        ;
      else if (unformat (line_input, "class %d", &opt_class))
        ;
      else if (unformat (line_input, "type %d", &type))
        ;
      else if (unformat (line_input, "length %d", &length))
        ;
      else if (unformat (line_input, "data-type raw"))
        data_type = GENEVE_OPT_TYPE_RAW;
      else if (unformat (line_input, "data-type ipv4"))
        data_type = GENEVE_OPT_TYPE_IPV4;
      else if (unformat (line_input, "data-type ipv6"))
        data_type = GENEVE_OPT_TYPE_IPV6;
      else if (unformat (line_input, "data-type uint8"))
        data_type = GENEVE_OPT_TYPE_UINT8;
      else if (unformat (line_input, "data-type uint16"))
        data_type = GENEVE_OPT_TYPE_UINT16;
      else if (unformat (line_input, "data-type uint32"))
        data_type = GENEVE_OPT_TYPE_UINT32;
      else if (unformat (line_input, "data-type string"))
        data_type = GENEVE_OPT_TYPE_STRING;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  /* Validate inputs */
  if (name == NULL)
    {
      error = clib_error_return (0, "option name required");
      goto done;
    }

  if (length == 0)
    {
      error = clib_error_return (0, "length must be greater than 0");
      goto done;
    }

  /* Validate data type against length */
  switch (data_type)
    {
    case GENEVE_OPT_TYPE_IPV4:
      if (length < 4)
        {
          error = clib_error_return (0, "length must be at least 4 bytes for IPv4 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_IPV6:
      if (length < 16)
        {
          error = clib_error_return (0, "length must be at least 16 bytes for IPv6 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_UINT8:
      if (length < 1)
        {
          error = clib_error_return (0, "length must be at least 1 byte for uint8 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_UINT16:
      if (length < 2)
        {
          error = clib_error_return (0, "length must be at least 2 bytes for uint16 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_UINT32:
      if (length < 4)
        {
          error = clib_error_return (0, "length must be at least 4 bytes for uint32 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_STRING:
      /* Strings need at least 1 byte for the null terminator */
      if (length < 1)
        {
          error = clib_error_return (0, "length must be at least 1 byte for string data type");
          goto done;
        }
      break;

    default:
      /* Raw type has no constraints */
      break;
    }

  /* Register the option */
  geneve_pcapng_register_option_def ((char *)name, opt_class, type, length, data_type);
  vlib_cli_output (vm, "Registered GENEVE option: name=%s, class=0x%x, type=0x%x, length=%d, data-type=%s",
                  name, opt_class, type, length,
                  data_type == GENEVE_OPT_TYPE_RAW ? "raw" :
                  data_type == GENEVE_OPT_TYPE_IPV4 ? "ipv4" :
                  data_type == GENEVE_OPT_TYPE_IPV6 ? "ipv6" :
                  data_type == GENEVE_OPT_TYPE_UINT8 ? "uint8" :
                  data_type == GENEVE_OPT_TYPE_UINT16 ? "uint16" :
                  data_type == GENEVE_OPT_TYPE_UINT32 ? "uint32" :
                  data_type == GENEVE_OPT_TYPE_STRING ? "string" : "unknown");

done:
  unformat_free (line_input);
  return error;
}

/* Helper function to format data type as string */
static u8 *
format_geneve_data_type (u8 * s, va_list * args)
{
  geneve_opt_data_type_t type = va_arg (*args, int);  /* enum is promoted to int */

  switch (type)
    {
    case GENEVE_OPT_TYPE_RAW:
      return format (s, "raw");
    case GENEVE_OPT_TYPE_IPV4:
      return format (s, "ipv4");
    case GENEVE_OPT_TYPE_IPV6:
      return format (s, "ipv6");
    case GENEVE_OPT_TYPE_UINT8:
      return format (s, "uint8");
    case GENEVE_OPT_TYPE_UINT16:
      return format (s, "uint16");
    case GENEVE_OPT_TYPE_UINT32:
      return format (s, "uint32");
    case GENEVE_OPT_TYPE_STRING:
      return format (s, "string");
    default:
      return format (s, "unknown");
    }
}

/* Show registered GENEVE options */
static clib_error_t *
geneve_pcapng_show_options_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u32 i;

  vlib_cli_output (vm, "Registered GENEVE options:");
  vlib_cli_output (vm, "%-20s %-10s %-10s %-10s %s",
                  "Name", "Class", "Type", "Length", "Data Type");
  vlib_cli_output (vm, "%-20s %-10s %-10s %-10s %s",
                  "--------------------", "----------", "----------", "----------", "----------");

  /* Display all registered options */
  for (i = 0; i < vec_len (gpm->option_defs); i++)
    {
      geneve_option_def_t *opt = &gpm->option_defs[i];
      vlib_cli_output (vm, "%-20s 0x%-8x %-10u %-10u %U",
                      opt->option_name, opt->opt_class, opt->type, opt->length,
                      format_geneve_data_type, opt->preferred_type);
    }

  return 0;
}

/* Helper function to format option data based on its type */
static u8 *
format_option_data (u8 * s, va_list * args)
{
  u8 *data = va_arg (*args, u8 *);
  u8 data_len = va_arg (*args, int);  /* promoted to int */
  geneve_opt_data_type_t type = va_arg (*args, int);  /* enum promoted to int */
  
  if (!data || data_len == 0)
    return format (s, "(empty)");
    
  switch (type)
    {
    case GENEVE_OPT_TYPE_IPV4:
      {
        ip4_address_t *ip4 = (ip4_address_t *)data;
        return format (s, "%U", format_ip4_address, ip4);
      }
      
    case GENEVE_OPT_TYPE_IPV6:
      {
        ip6_address_t *ip6 = (ip6_address_t *)data;
        return format (s, "%U", format_ip6_address, ip6);
      }
      
    case GENEVE_OPT_TYPE_UINT8:
      {
        u8 val = data[0];
        return format (s, "%u", val);
      }
      
    case GENEVE_OPT_TYPE_UINT16:
      {
        u16 val = clib_net_to_host_u16(*(u16 *)data);
        return format (s, "%u", val);
      }
      
    case GENEVE_OPT_TYPE_UINT32:
      {
        u32 val = clib_net_to_host_u32(*(u32 *)data);
        return format (s, "%u", val);
      }
      
    case GENEVE_OPT_TYPE_STRING:
      {
        /* Ensure null-termination */
        char *str = (char *)vec_dup (data);
        str[data_len - 1] = '\0';
        s = format (s, "\"%s\"", str);
        vec_free (str);
        return s;
      }
      
    case GENEVE_OPT_TYPE_RAW:
    default:
      {
        /* Display as hex bytes */
        int i;
        for (i = 0; i < data_len; i++)
          {
            s = format (s, "%02x", data[i]);
            if (i < data_len - 1)
              s = format (s, " ");
          }
        return s;
      }
    }
}

/* Show active GENEVE capture filters */
static clib_error_t *
geneve_pcapng_show_filters_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u32 sw_if_index;
  u32 i, j;
  int filters_displayed = 0;
  
  vlib_cli_output (vm, "GENEVE Capture Filters:");

  /* Display global filters first */
  if (vec_len(gpm->global_filters) > 0)
  {
    vlib_cli_output (vm, "\nGlobal Filters (applied to all interfaces):");
    
    for (i = 0; i < vec_len(gpm->global_filters); i++)
    {
      geneve_capture_filter_t *filter = &gpm->global_filters[i];
      
      vlib_cli_output (vm, "  Filter ID: %u", filter->filter_id);
      
      /* FIXME: Display filter details as in original code below */
      
      filters_displayed++;
    }
  }
  
  /* Display filters for each interface */
  for (sw_if_index = 0; sw_if_index < vec_len (gpm->per_interface); sw_if_index++)
    {
      if (gpm->per_interface[sw_if_index].filters == 0)
        continue;
        
      if (vec_len (gpm->per_interface[sw_if_index].filters) == 0)
        continue;
        
      vnet_sw_interface_t *sw = vnet_get_sw_interface (vnet_get_main(), sw_if_index);
      if (!sw)
        continue;
        
      vlib_cli_output (vm, "\nInterface: %U (idx %d) - Capture %s",
                      format_vnet_sw_interface_name, vnet_get_main(), sw,
                      sw_if_index,
                      gpm->per_interface[sw_if_index].capture_enabled ? 
                      "enabled" : "disabled");
                      
      /* Display each filter on this interface */
      for (i = 0; i < vec_len (gpm->per_interface[sw_if_index].filters); i++)
        {
          geneve_capture_filter_t *filter = &gpm->per_interface[sw_if_index].filters[i];
          
          vlib_cli_output (vm, "  Filter ID: %u", filter->filter_id);

/* For each filter, also display the 5-tuple filters */
  if (filter->outer_filter_present)
    {
      vlib_cli_output (vm, "%U", format_header_filter,
                      filter->outer_header_mask,
                      filter->outer_header_value,
                      filter->outer_header_length,
                      0 /* is_inner */);
    }
    
  if (filter->inner_filter_present)
    {
      vlib_cli_output (vm, "%U", format_header_filter,
                      filter->inner_header_mask,
                      filter->inner_header_value,
                      filter->inner_header_length,
                      1 /* is_inner */);
    }
          
          /* Basic header filters */
          if (filter->ver_present)
            vlib_cli_output (vm, "    Version: %u", filter->ver);
            
          if (filter->opt_len_present)
            vlib_cli_output (vm, "    Option Length: %u", filter->opt_len);
            
          if (filter->proto_present)
            vlib_cli_output (vm, "    Protocol: 0x%04x", filter->protocol);
            
          if (filter->vni_present)
            vlib_cli_output (vm, "    VNI: %u", filter->vni);
            
          /* Option filters */
          if (filter->option_filters)
            {
              vlib_cli_output (vm, "    Option Filters:");
              
              for (j = 0; j < vec_len (filter->option_filters); j++)
                {
                  if (!filter->option_filters[j].present)
                    continue;
                    
                  /* Determine option details */
                  u16 opt_class;
                  u8 opt_type;
                  char *name = NULL;
                  geneve_opt_data_type_t data_type = GENEVE_OPT_TYPE_RAW;
                  
                  if (filter->option_filters[j].option_name)
                    {
                      /* Look up registered option by name */
                      uword *p = hash_get_mem (gpm->option_by_name, 
                                             filter->option_filters[j].option_name);
                      if (p)
                        {
                          geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
                          opt_class = opt_def->opt_class;
                          opt_type = opt_def->type;
                          name = opt_def->option_name;
                          data_type = opt_def->preferred_type;
                        }
                      else
                        {
                          /* This shouldn't happen if validation was done at filter creation */
                          opt_class = 0;
                          opt_type = 0;
                          name = (char *)filter->option_filters[j].option_name;
                        }
                    }
                  else
                    {
                      /* Direct class/type specification */
                      opt_class = filter->option_filters[j].opt_class;
                      opt_type = filter->option_filters[j].type;
                      
                      /* Try to find a registered name for this option */
                      u64 key = ((u64)opt_class << 8) | opt_type;
                      uword *p = hash_get (gpm->option_by_class_type, key);
                      if (p)
                        {
                          geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
                          name = opt_def->option_name;
                          data_type = opt_def->preferred_type;
                        }
                    }
                    
                  /* Output option filter details */
                  if (name)
                    vlib_cli_output (vm, "      Option: %s (class=0x%x, type=0x%x)",
                                    name, opt_class, opt_type);
                  else
                    vlib_cli_output (vm, "      Option: class=0x%x, type=0x%x",
                                    opt_class, opt_type);
                                    
                  if (filter->option_filters[j].match_any)
                    {
                      vlib_cli_output (vm, "        Match: Any (presence only)");
                    }
                  else if (filter->option_filters[j].data)
                    {
                      /* Show data in both formatted and raw forms */
                      vlib_cli_output (vm, "        Match Value: %U",
                                      format_option_data,
                                      filter->option_filters[j].data,
                                      filter->option_filters[j].data_len,
                                      data_type);
                                      
                      /* For non-raw types, also show raw bytes */
                      if (data_type != GENEVE_OPT_TYPE_RAW)
                        {
                          vlib_cli_output (vm, "        Raw Bytes: %U",
                                          format_option_data,
                                          filter->option_filters[j].data,
                                          filter->option_filters[j].data_len,
                                          GENEVE_OPT_TYPE_RAW);
                        }
                        
                      /* Show mask if present */
                      if (filter->option_filters[j].mask)
                        {
                          vlib_cli_output (vm, "        Mask: %U",
                                          format_option_data,
                                          filter->option_filters[j].mask,
                                          filter->option_filters[j].data_len,
                                          GENEVE_OPT_TYPE_RAW);
                        }
                    }
                }
            }
          
          filters_displayed++;
        }
    }
    
  if (filters_displayed == 0)
    vlib_cli_output (vm, "  No active filters");
    
  return 0;
}

/* CLI command to show active filters */
VLIB_CLI_COMMAND (geneve_pcapng_show_filters_command, static) = {
  .path = "show geneve pcapng filters",
  .short_help = "show geneve pcapng filters",
  .function = geneve_pcapng_show_filters_command_fn,
};

/* Updated CLI command to register a named GENEVE option */
VLIB_CLI_COMMAND (geneve_pcapng_register_option_command, static) = {
  .path = "geneve pcapng register-option",
  .short_help = "geneve pcapng register-option name <name> class <class> type <type> length <length>"
                " [data-type raw|ipv4|ipv6|uint8|uint16|uint32|string]",
  .function = geneve_pcapng_register_option_command_fn,
};

/* CLI command to show registered options */
VLIB_CLI_COMMAND (geneve_pcapng_show_options_command, static) = {
  .path = "show geneve pcapng options",
  .short_help = "show geneve pcapng options",
  .function = geneve_pcapng_show_options_command_fn,
};

/* CLI command to enable or disable capture */
VLIB_CLI_COMMAND (geneve_pcapng_enable_command, static) = {
  .path = "geneve pcapng capture",
  .short_help = "geneve pcapng capture interface <interface> [disable]",
  .function = geneve_pcapng_enable_command_fn,
};

/*
 * File output initialization for GENEVE PCAPng plugin
 *
 * This code needs to be added to ensure proper connection between
 * the plugin and file output functions.
 */

static void
geneve_pcapng_output_init (geneve_pcapng_main_t *gpm)
{
  /* Set up file output implementation */
  gpm->output.init = file_output_init;
  gpm->output.cleanup = file_output_cleanup;
  gpm->output.write_pcapng_shb = file_write_pcapng_shb;
  gpm->output.write_pcapng_idb = file_write_pcapng_idb;
  gpm->output.write_pcapng_epb = file_write_pcapng_epb;
}

/* Add CLI command to select output type (e.g. file, TLS) */
static clib_error_t *
geneve_pcapng_output_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u8 use_file_output = 1;  /* Default to file output */

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "file"))
        use_file_output = 1;
      /* In future, could add: else if (unformat (line_input, "tls")) */
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  /* Cleanup existing output contexts if any */
  if (gpm->worker_output_ctx)
    {
      u32 i;
      for (i = 0; i < vec_len (gpm->worker_output_ctx); i++)
        {
          if (gpm->worker_output_ctx[i])
            {
              if (gpm->output.cleanup)
                gpm->output.cleanup (gpm->worker_output_ctx[i]);
              gpm->worker_output_ctx[i] = NULL;
            }
        }
    }

  /* Set output implementation */
  if (use_file_output)
    {
      geneve_pcapng_output_init (gpm);
      vlib_cli_output (vm, "GENEVE PCAPng capture will use file output");
    }
  /* In future: else if (use_tls_output) { tls_output_init (gpm); } */

done:
  unformat_free (line_input);
  return error;
}

/* Add CLI command definition */
VLIB_CLI_COMMAND (geneve_pcapng_output_command, static) = {
  .path = "geneve pcapng output",
  .short_help = "geneve pcapng output [file]",
  .function = geneve_pcapng_output_command_fn,
};

/* Update geneve_pcapng_init to properly set output implementation */
static clib_error_t *
geneve_pcapng_init (vlib_main_t * vm)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u32 num_workers;

  /* Initialize hash tables */
  gpm->option_by_name = hash_create_string (0, sizeof (uword));
  gpm->option_by_class_type = hash_create (0, sizeof (uword));

  /* Set up default file output implementation */
  geneve_pcapng_output_init (gpm);

  /* Allocate per-worker output contexts */
  num_workers = vlib_num_workers ();
  vec_validate (gpm->worker_output_ctx, num_workers);

#ifdef XXXXX
  /* Register for the GENEVE input feature arc */
  gpm->ip4_geneve_input_arc = vlib_node_add_named_next (
      vm, vlib_get_node_by_name (vm, (u8 *) "ip4-geneve-input")->index,
      "geneve-pcapng-capture");

  gpm->ip6_geneve_input_arc = vlib_node_add_named_next (
      vm, vlib_get_node_by_name (vm, (u8 *) "ip6-geneve-input")->index,
      "geneve-pcapng-capture");

#endif

  /* Register some basic GENEVE option definitions */
  geneve_pcapng_register_option_def ("vpp-metadata", 0x0123, 0x01, 8, GENEVE_OPT_TYPE_STRING);
  geneve_pcapng_register_option_def ("legacy-oam", 0x0F0F, 0x01, 4, GENEVE_OPT_TYPE_UINT32);
  register_default_options();

  return 0;
}

/* Register the initialization function */
VLIB_INIT_FUNCTION (geneve_pcapng_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Geneve Tunnel Packet Capture plugin",
};

