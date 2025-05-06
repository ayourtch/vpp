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
typedef struct geneve_output_t geneve_output_t;

/* API declarations */
static clib_error_t *geneve_pcapng_init (vlib_main_t * vm);
void geneve_pcapng_register_option_def (const char *name, u16 class, u8 type, u8 length);
int geneve_pcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter);
int geneve_pcapng_del_filter (u32 sw_if_index, u32 filter_id);
int geneve_pcapng_enable_capture (u32 sw_if_index, u8 enable);

/* Option definition for user-friendly filtering */
struct geneve_option_def_t {
  char *name;               /* Friendly name for the option */
  u16 opt_class;            /* Class field */
  u8 type;                  /* Type field */
  u8 length;                /* Length in bytes of the option data */
  format_function_t *format_fn; /* Optional format function for displaying option */
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
  
  /* Geneve option filters */
  struct {
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
  } *option_filters;       /* Vector of option filters */
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
  snprintf (filename, sizeof (filename), "geneve_capture_worker%u.pcapng", worker_index);
  ctx->filename = (void *)format (0, "%s%c", filename, 0);
  
  ctx->file = fopen ((char *) ctx->filename, "wb");
  if (!ctx->file)
    {
      clib_warning ("Failed to create PCAPng file: %s", ctx->filename);
      vec_free (ctx->filename);
      clib_mem_free (ctx);
      return NULL;
    }
  
  return ctx;
}

static void
file_output_cleanup (void *context)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  
  if (!ctx)
    return;
    
  if (ctx->file)
    fclose (ctx->file);
    
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
  } shb;
  
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
  total_len = 20 + name_len + pad_len;
  
  block = clib_mem_alloc (total_len);
  if (!block)
    return -1;
  
  /* Fill in the IDB block */
  *(u32 *)(block) = PCAPNG_BLOCK_TYPE_IDB;
  *(u32 *)(block + 4) = total_len;
  *(u16 *)(block + 8) = 1;  /* Link type: LINKTYPE_ETHERNET */
  *(u16 *)(block + 10) = 0; /* Reserved */
  *(u32 *)(block + 12) = 0; /* SnapLen: no limit */
  
  /* Copy interface name to the options section */
  memcpy (block + 16, if_name, name_len - 1);
  block[16 + name_len - 1] = 0;  /* Ensure null termination */
  
  /* Add padding bytes */
  memset (block + 16 + name_len, 0, pad_len);
  
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
  total_len = 28 + packet_len + pad_len;
  
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
geneve_packet_matches_filter (geneve_pcapng_main_t *gpm,
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

/* Filter and capture Geneve packets */
static uword
geneve_pcapng_node_fn (vlib_main_t *vm,
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
          
          /* Skip interfaces where capture is not enabled */
          if (sw_if_index0 >= vec_len (gpm->per_interface) ||
              !gpm->per_interface[sw_if_index0].capture_enabled)
            {
              goto packet_done;
            }
          
          /* Parse either IPv4 or IPv6 header */
          ip4 = vlib_buffer_get_current (b0);
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
                  
                  gpm->output.write_pcapng_idb (output_ctx, sw_if_index0, (char *)if_name);
                  
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
VLIB_REGISTER_NODE (geneve_pcapng_node) = {
  .function = geneve_pcapng_node_fn,
  .name = "geneve-pcapng-capture",
  .vector_size = sizeof (u32),
  .format_trace = 0, /* No tracing */
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

/******************************************************************************
 * API and initialization
 ******************************************************************************/

void
geneve_pcapng_register_option_def (const char *name, u16 class, u8 type, u8 length)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  geneve_option_def_t opt_def = {0};
  u64 key;
  u32 index;
  
  /* Create option definition */
  opt_def.name = (void *)format (0, "%s%c", name, 0);
  opt_def.opt_class = class;
  opt_def.type = type;
  opt_def.length = length;
  
  /* Add to vector */
  index = vec_len (gpm->option_defs);
  vec_add1 (gpm->option_defs, opt_def);
  
  /* Add to hash tables */
  hash_set_mem (gpm->option_by_name, opt_def.name, index);
  
  key = ((u64)class << 8) | type;
  hash_set (gpm->option_by_class_type, key, index);
}

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



/* 
 * CLI commands for GENEVE PCAPng plugin
 * These commands should be added to the implementation of the plugin.
 */

/* CLI command function implementations */

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
    
  /* Register the option */
  geneve_pcapng_register_option_def ((char *)name, opt_class, type, length);
  vlib_cli_output (vm, "Registered GENEVE option: name=%s, class=0x%x, type=0x%x, length=%d",
                  name, opt_class, type, length);
  
done:
  unformat_free (line_input);
  return error;
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

static clib_error_t *
geneve_pcapng_filter_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  geneve_capture_filter_t filter = {0};
  u32 sw_if_index = ~0;
  u8 is_add = 1;
  u32 filter_id = ~0;
  
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
      /* Additional option filters would be handled here */
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

/* CLI command to register a named GENEVE option */
VLIB_CLI_COMMAND (geneve_pcapng_register_option_command, static) = {
  .path = "geneve pcapng register-option",
  .short_help = "geneve pcapng register-option name <name> class <class> type <type> length <length>",
  .function = geneve_pcapng_register_option_command_fn,
};

/* CLI command to enable or disable capture */
VLIB_CLI_COMMAND (geneve_pcapng_enable_command, static) = {
  .path = "geneve pcapng capture",
  .short_help = "geneve pcapng capture interface <interface> [disable]",
  .function = geneve_pcapng_enable_command_fn,
};

/* CLI command to add or delete filters */
VLIB_CLI_COMMAND (geneve_pcapng_filter_command, static) = {
  .path = "geneve pcapng filter",
  .short_help = "geneve pcapng filter interface <interface> [ver <ver>] [opt-len <len>] [protocol <proto>] [vni <vni>] [del id <id>]",
  .function = geneve_pcapng_filter_command_fn,
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
  geneve_pcapng_register_option_def ("vpp-metadata", 0x0123, 0x01, 8);
  geneve_pcapng_register_option_def ("legacy-oam", 0x0F0F, 0x01, 4);

  return 0;
}

/* Register the initialization function */
VLIB_INIT_FUNCTION (geneve_pcapng_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Tunnel Packet Capture plugin",
};

