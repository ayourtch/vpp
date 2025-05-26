/*
 * geneve_pcapng.c - GENEVE packet capture plugin for VPP
 *
 * Captures GENEVE tunneled packets (IPv4/IPv6) to PCAPng files
 * with support for filtering based on GENEVE options and 5-tuple.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <isa-l/igzip_lib.h> // Using only igzip headers

#define CHUNK_SIZE (1 << 20) // 1MB buffer


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

/* Filter scope */
#define FILTER_SCOPE_INTERFACE    0
#define FILTER_SCOPE_GLOBAL       1

/* Forward declarations */
typedef struct geneve_pcapng_main_t geneve_pcapng_main_t;
typedef struct geneve_option_def_t geneve_option_def_t;
typedef struct geneve_capture_filter_t geneve_capture_filter_t;
typedef struct geneve_option_filter_t geneve_option_filter_t;
typedef struct geneve_tuple_filter_t geneve_tuple_filter_t;
typedef struct geneve_output_t geneve_output_t;

static geneve_pcapng_main_t *get_geneve_pcapng_main ();

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

/* 5-tuple filter structure for IP/transport layer filtering */
struct geneve_tuple_filter_t {
  u8 *value;              /* Byte vector with exact values to match */
  u8 *mask;               /* Byte vector with masks for matching (1 bits are checked) */
  u32 length;             /* Length of the vectors */
};

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
int geneve_pcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter, u8 is_global);
int geneve_pcapng_del_filter (u32 sw_if_index, u32 filter_id, u8 is_global);
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
  
  /* 5-tuple filters for outer and inner headers */
  u8 outer_tuple_present;  /* 1 if outer 5-tuple filter is active */
  geneve_tuple_filter_t outer_tuple;  /* Outer 5-tuple filter */
  
  u8 inner_tuple_present;  /* 1 if inner 5-tuple filter is active */
  geneve_tuple_filter_t inner_tuple;  /* Inner 5-tuple filter */
  
  geneve_option_filter_t *option_filters;       /* Vector of option filters */
};

/* Output interface definition for extensibility */
struct geneve_output_t {
  void *(*init) (u32 worker_index);
  void (*cleanup) (void *ctx);
  int (*chunk_write) (void *ctx, const void *chunk, size_t chunk_size);
  void (*flush) (void *context);
  int (*write_pcapng_shb) (geneve_output_t *out, void *ctx);
  int (*write_pcapng_idb) (geneve_output_t *out, void *ctx, u32 if_index, const char *if_name);
  int (*write_pcapng_epb) (geneve_output_t *out, void *ctx, u32 if_index, u64 timestamp, 
                           u32 orig_len, void *packet_data, u32 packet_len);
  /* Can be extended with additional methods */
};

/* File-based output implementation */
typedef struct {
  FILE *file;
  char *filename;
} file_output_ctx_t;

typedef struct {
    gzFile gz_file;
    char *filename;
    int fd;
} gzfile_output_ctx_t;

typedef struct {
    char *filename;
    int fd;
    // Using direct igzip structures
    struct isal_zstream stream;
    struct isal_gzip_header gzip_hdr;

    unsigned char *out_buf;
    unsigned char *level_buf;
} igzfile_output_ctx_t;

void* pcapng_igzip_start(u32 worker_index) {
    igzfile_output_ctx_t *ctx;
    char filename[256];
  
  ctx = clib_mem_alloc_aligned (sizeof (igzfile_output_ctx_t), CLIB_CACHE_LINE_BYTES);
  memset (ctx, 0, sizeof (*ctx));

  /* Create a unique filename per worker */
  snprintf (filename, sizeof (filename), "/tmp/geneve_capture_worker%u.pcapng.gz", worker_index);
  ctx->filename = (void *)format (0, "%s%c", filename, 0);

    if (!ctx) {
        return NULL;
    }

    // Open the file with appropriate flags for syncing
    int fd = open(ctx->filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        clib_mem_free(ctx);
        return NULL;
    }
    ctx->fd = fd;

    // Initialize header
    isal_gzip_header_init(&ctx->gzip_hdr);

    // Initialize compression stream directly
    isal_deflate_init(&ctx->stream);
    ctx->stream.end_of_stream = 0;
    ctx->stream.flush = NO_FLUSH;
    ctx->stream.gzip_flag = IGZIP_GZIP; // Using gzip format
    ctx->stream.level = 1; // Fastest compression
    // Allocate memory buffers
    ctx->out_buf = clib_mem_alloc(CHUNK_SIZE);
    ctx->level_buf = malloc(ISAL_DEF_LVL1_DEFAULT);
/*
    if (!in_buf || !out_buf || !level_buf) {
        perror("Memory allocation failed");
        return 1;
    }
    */
    
    // Setup level buffer - critical for performance
    ctx->stream.level_buf = ctx->level_buf;
    ctx->stream.level_buf_size = ISAL_DEF_LVL1_DEFAULT;
    
    // Setup output buffer
    ctx->stream.avail_out = CHUNK_SIZE;
    ctx->stream.next_out = ctx->out_buf;
    
    // Direct CPU feature detection for optimal performance
    // This isn't in the standard API but is available in igzip internals
    #ifdef HAVE_CPUID
    // Use CPU dispatch directly, forces optimal code path selection
    struct inflate_state *state = &ctx->stream.internal_state;
    state->crc_fold_model = determine_igzip_hufftables();
    #endif

    return ctx;
}

int pcapng_igzip_write_chunk(void *context, const void *chunk, size_t chunk_size) {
     igzfile_output_ctx_t *ctx = context;
     ctx->stream.avail_in = chunk_size;
     ctx->stream.next_in = (uint8_t *) chunk;

     /*
     // Set end of stream flag on last chunk
        if (bytes_read < CHUNK_SIZE)
            stream.end_of_stream = 1; 
      */
        // Compress data - direct call to core function
     int ret = isal_deflate(&ctx->stream);
     if (ret != ISAL_DECOMP_OK) {
         fprintf(stderr, "Error during compression: %d\n", ret);
         return 1;
     }
        
        // Write compressed output
     size_t bytes_compressed = CHUNK_SIZE - ctx->stream.avail_out;
     int result = write(ctx->fd, ctx->out_buf, bytes_compressed);
     if (result != bytes_compressed) {
        return -1;
     }
        
        // Reset output buffer for next chunk
     ctx->stream.next_out = ctx->out_buf;
     ctx->stream.avail_out = CHUNK_SIZE;
/*
    
    // Flush any remaining data if needed
    if (stream.internal_state.state != ZSTATE_END) {
        do {
            // Direct call to flush remaining data
            int ret = isal_deflate(&stream);
            if (ret != ISAL_DECOMP_OK) {
                fprintf(stderr, "Error during flush: %d\n", ret);
                break;
            }
            
            // Write any output generated
            size_t bytes_compressed = CHUNK_SIZE - stream.avail_out;
            if (bytes_compressed > 0) {
                write(out_fd, out_buf, bytes_compressed);
                stream.next_out = out_buf;
                stream.avail_out = CHUNK_SIZE;
            }
        } while (stream.internal_state.state != ZSTATE_END);
    }
*/
    return 0;

}

static void
pcapng_igzip_flush(void *context) {
}

static void pcapng_igzip_finish(void *context) {
    igzfile_output_ctx_t *writer = context;
    if (!writer) {
        return;
    }

    // Free resources
    clib_mem_free(writer->filename);
    clib_mem_free(writer);

    return;
}

/*
 * HTTP streaming output implementation for GENEVE PCAPng capture
 * Streams captured packets via HTTP POST to a remote server
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_content_types.h>

typedef struct
{
    /* HTTP client state */
    u32 app_index;
    session_t *session;
    u32 worker_index;

    /* Streaming buffer management */
    u8 *send_buffer;
    u32 buffer_size;
    u32 bytes_pending;

    /* HTTP request state */
    http_msg_t msg;
    u8 *headers_buf;
    http_headers_ctx_t req_headers;
    u8 *target_uri;

    /* Connection state */
    u8 connected;
    u8 headers_sent;
    session_endpoint_cfg_t connect_sep;

    /* Statistics */
    u64 total_bytes_sent;
    u64 chunks_sent;
} http_pcapng_ctx_t;

/* Forward declarations for HTTP client callbacks */
static int http_pcapng_session_connected_callback (u32 app_index,
						   u32 session_index,
						   session_t *s,
						   session_error_t err);
static int http_pcapng_rx_callback (session_t *s);
static int http_pcapng_tx_callback (session_t *s);
static void http_pcapng_session_disconnect_callback (session_t *s);
static void http_pcapng_session_reset_callback (session_t *s);

static int
http_pcapng_accept_callback (session_t *s)
{
    return 0;
}

static session_cb_vft_t http_pcapng_session_cb_vft = {
  .session_accept_callback = http_pcapng_accept_callback,
  .session_connected_callback = http_pcapng_session_connected_callback,
  .session_disconnect_callback = http_pcapng_session_disconnect_callback,
  .session_reset_callback = http_pcapng_session_reset_callback,
  .builtin_app_rx_callback = http_pcapng_rx_callback,
  .builtin_app_tx_callback = http_pcapng_tx_callback,
};
/*
static int
pcapng_http_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning (0, "connect returned: %U", format_session_error, rv);

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
  return rv;
}

static void
pcapng_program_connect (vnet_connect_args_t *a)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
pcapng_http_connect_rpc, a);
}
*/

static void
enable_session_manager (vlib_main_t *vm)
{
    session_enable_disable_args_t args = { .is_en = 1,
					   .rt_engine_type =
					     RT_BACKEND_ENGINE_RULE_TABLE };
    vlib_worker_thread_barrier_sync (vm);
    vnet_session_enable_disable (vm, &args);
    vlib_worker_thread_barrier_release (vm);
}

/**
 * Initialize HTTP streaming context for PCAPng capture
 * @param worker_index Worker thread index
 * @return Initialized context or NULL on error
 */
void *
http_pcapng_init (u32 worker_index)
{
    http_pcapng_ctx_t *ctx;
    vnet_app_attach_args_t attach_args;
    u64 options[18];
    int rv;

    /* Allocate and initialize context */
    ctx = clib_mem_alloc_aligned (sizeof (http_pcapng_ctx_t),
				  CLIB_CACHE_LINE_BYTES);
    if (!ctx)
    {
	clib_warning ("Failed to allocate HTTP PCAPng context");
	return NULL;
    }
    memset (ctx, 0, sizeof (*ctx));

    ctx->worker_index = worker_index;
    ctx->buffer_size = 64 * 1024; /* 64KB buffer */
    ctx->send_buffer = clib_mem_alloc (ctx->buffer_size);
    if (!ctx->send_buffer)
    {
	clib_warning ("Failed to allocate send buffer");
	clib_mem_free (ctx);
	return NULL;
    }

    /* Initialize HTTP headers buffer */
    vec_validate (ctx->headers_buf, 4095); /* 4KB for headers */
    http_init_headers_ctx (&ctx->req_headers, ctx->headers_buf,
			   vec_len (ctx->headers_buf));

    /* Set target URI */
    ctx->target_uri =
      format (0, "/upload/file.pcapng%c", 0);

    /* Setup HTTP application attachment */
    clib_memset (&attach_args, 0, sizeof (attach_args));
    clib_memset (options, 0, sizeof (options));

    attach_args.api_client_index = APP_INVALID_INDEX;
    attach_args.name = format (0, "http_pcapng_worker_%u", worker_index);
    attach_args.session_cb_vft = &http_pcapng_session_cb_vft;
    attach_args.options = options;
    attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = 32 << 20;	  /* 32MB */
    attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20; /* 32MB */
    attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = 8 << 10;	  /* 8KB */
    attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] =
      256 << 10; /* 256KB for streaming */
    attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

    rv = vnet_application_attach (&attach_args);
    if (rv)
    {
	clib_warning ("HTTP PCAPng app attach failed: %U",
		      format_session_error, rv);
	vec_free (ctx->headers_buf);
	vec_free (ctx->target_uri);
	vec_free (attach_args.name);
	clib_mem_free (ctx->send_buffer);
	clib_mem_free (ctx);
	return NULL;
    }

    ctx->app_index = attach_args.app_index;
    vec_free (attach_args.name);

    clib_memset (&ctx->connect_sep, 0, sizeof (ctx->connect_sep));
    rv = parse_uri ("http://172.17.1.1:3000/upload/file.pcapng",
		    &ctx->connect_sep);
    if (rv)
    {
	clib_warning ("Failed to parse target URI: %U", format_session_error,
		      rv);
	/* Cleanup and return NULL */
	vnet_app_detach_args_t detach = { .app_index = ctx->app_index };
	vnet_application_detach (&detach);
	vec_free (ctx->headers_buf);
	vec_free (ctx->target_uri);
	clib_mem_free (ctx->send_buffer);
	clib_mem_free (ctx);
	return NULL;
    }

    /* Initiate connection */
    transport_endpt_ext_cfg_t *ext_cfg;
    transport_endpt_cfg_http_t http_cfg = {
      (u32) 3600, 0
    }; /* 1 hour timeout for streaming */

    vnet_connect_args_t connect_args;
    clib_memset (&connect_args, 0, sizeof (connect_args));
    ext_cfg = session_endpoint_add_ext_cfg (
      &connect_args.sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
    clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

    clib_memcpy (&connect_args.sep_ext, &ctx->connect_sep,
		 sizeof (ctx->connect_sep));
    connect_args.app_index = ctx->app_index;

    connect_args.api_context = worker_index;

    rv = vnet_connect (&connect_args);
    if (rv)
    {
	clib_warning ("HTTP PCAPng connect failed: %U", format_session_error,
		      rv);
	// Cleanup and return NULL
	vnet_app_detach_args_t detach = { .app_index = ctx->app_index };
	vnet_application_detach (&detach);
	vec_free (ctx->headers_buf);
	vec_free (ctx->target_uri);
	clib_mem_free (ctx->send_buffer);
	clib_mem_free (ctx);
	return NULL;
    }

    return ctx;
}

/**
 * Write a chunk of PCAPng data to HTTP stream
 * @param context HTTP PCAPng context
 * @param chunk Data chunk to write
 * @param chunk_size Size of data chunk
 * @return 0 on success, -1 on error
 */
int
http_pcapng_chunk_write (void *context, const void *chunk, size_t chunk_size)
{
    http_pcapng_ctx_t *ctx = (http_pcapng_ctx_t *) context;

    if (!ctx || !ctx->connected)
    {
	return -1;
    }

    /* Check if we need to send headers first */
    if (!ctx->headers_sent)
    {
	clib_warning ("sending streaming PUT request");

	/* Setup HTTP PUT headers for streaming */
	ctx->msg.method_type = HTTP_REQ_PUT;
	ctx->msg.type = HTTP_MSG_REQUEST;
	ctx->msg.data.type = HTTP_MSG_DATA_STREAMING;

	/* Set message lengths */
	ctx->msg.data.target_path_len = vec_len (ctx->target_uri) - 1;
	ctx->msg.data.headers_len = ctx->req_headers.tail_offset;
	ctx->msg.data.body_len = ~0ULL; /* Unknown length for streaming */

	ctx->msg.data.target_path_offset = 0;
	ctx->msg.data.headers_offset = ctx->msg.data.target_path_len;
	ctx->msg.data.body_offset =
	  ctx->msg.data.headers_offset + ctx->msg.data.headers_len;
	ctx->msg.data.len =
	  ctx->msg.data.target_path_len + ctx->msg.data.headers_len;

	/* Send HTTP headers */
	int rv = svm_fifo_enqueue (ctx->session->tx_fifo, sizeof (ctx->msg),
				   (u8 *) &ctx->msg);
	if (rv != sizeof (ctx->msg))
	  {
	    clib_warning ("Failed to enqueue HTTP message header");
	    return -1;
	  }

	/* Send target path */
	rv = svm_fifo_enqueue (ctx->session->tx_fifo,
			       ctx->msg.data.target_path_len, ctx->target_uri);
	if (rv != ctx->msg.data.target_path_len)
	  {
	    clib_warning ("Failed to enqueue target path");
	    return -1;
	  }

	/* Send headers */
	rv = svm_fifo_enqueue (ctx->session->tx_fifo,
			       ctx->req_headers.tail_offset, ctx->headers_buf);
	if (rv != ctx->req_headers.tail_offset)
	  {
	    clib_warning ("Failed to enqueue headers");
	    return -1;
	  }

	ctx->headers_sent = 1;

	/* Trigger TX event */
	if (svm_fifo_set_event (ctx->session->tx_fifo))
	  {
	    session_program_tx_io_evt (ctx->session->handle,
				       SESSION_IO_EVT_TX);
	  }
    }

    /* For streaming PUT, we just enqueue the raw data */
    /* The HTTP layer will handle chunked encoding */
    u32 max_enq = svm_fifo_max_enqueue (ctx->session->tx_fifo);
    if (max_enq < chunk_size)
    {
	/* Not enough space, would need to buffer */
	clib_warning ("tx fifo full, need %lu have %u", chunk_size, max_enq);
	return -1;
    }

    int rv =
      svm_fifo_enqueue (ctx->session->tx_fifo, chunk_size, (u8 *) chunk);
    if (rv < 0)
    {
	return -1;
    }

    ctx->total_bytes_sent += rv;
    ctx->chunks_sent++;

    /* Trigger TX event */
    if (svm_fifo_set_event (ctx->session->tx_fifo))
    {
	session_program_tx_io_evt (ctx->session->handle, SESSION_IO_EVT_TX);
    }

    return 0;
}

/**
 * Flush any pending data in HTTP stream
 * @param context HTTP PCAPng context
 */
void
http_pcapng_flush (void *context)
{
    http_pcapng_ctx_t *ctx = (http_pcapng_ctx_t *) context;

    if (!ctx || !ctx->connected || !ctx->session)
    {
	return;
    }

    /* For streaming PUT, we need to close the connection to signal end of data
     */
    /* The HTTP layer will send the final 0-sized chunk */

    /* Log statistics */
    clib_warning ("HTTP PCAPng worker %u: sent %lu bytes in %lu chunks",
		  ctx->worker_index, ctx->total_bytes_sent, ctx->chunks_sent);

    /* Disconnect the session to signal end of streaming */
    vnet_disconnect_args_t disconnect_args = { .handle =
						 session_handle (ctx->session),
					       .app_index = ctx->app_index };
    vnet_disconnect_session (&disconnect_args);

    ctx->connected = 0;
}

/**
 * Cleanup HTTP PCAPng context and close connection
 * @param context HTTP PCAPng context to cleanup
 */
void
http_pcapng_cleanup (void *context)
{
    http_pcapng_ctx_t *ctx = (http_pcapng_ctx_t *) context;

    if (!ctx)
    {
	return;
    }

    /* Disconnect session if connected */
    if (ctx->session && ctx->connected)
    {
	vnet_disconnect_args_t disconnect_args = {
	  .handle = session_handle (ctx->session), .app_index = ctx->app_index
	};
	vnet_disconnect_session (&disconnect_args);
    }

    /* Detach application */
    if (ctx->app_index != APP_INVALID_INDEX)
    {
	vnet_app_detach_args_t detach_args = { .app_index = ctx->app_index,
					       .api_client_index =
						 APP_INVALID_INDEX };
	vnet_application_detach (&detach_args);
    }

    /* Free allocated memory */
    if (ctx->send_buffer)
    {
	clib_mem_free (ctx->send_buffer);
    }

    vec_free (ctx->headers_buf);
    vec_free (ctx->target_uri);

    /* Free context */
    clib_mem_free (ctx);
}

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
  
  /* Global filters */
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

static geneve_pcapng_main_t *
get_geneve_pcapng_main ()
{
  return &geneve_pcapng_main;
}

/* HTTP Client Session Callbacks */

static int
http_pcapng_session_connected_callback (u32 app_index, u32 session_index,
					session_t *s, session_error_t err)
{
  http_pcapng_ctx_t *ctx = NULL;

  if (err)
    {
	clib_warning ("HTTP PCAPng connection failed: %U",
		      format_session_error, err);
	return -1;
    }

  /* Find context by app_index - this is simplified, in real implementation
   * you'd need a proper context lookup mechanism */
  /* For now, store context in session opaque */
  /*
  ctx =
    (http_pcapng_ctx_t *) uword_to_pointer (s->opaque, http_pcapng_ctx_t *);
  */
  geneve_pcapng_main_t *gpm = get_geneve_pcapng_main ();
  ctx = gpm->worker_output_ctx[s->opaque];
  if (!ctx)
    {
	clib_warning ("No context found for HTTP PCAPng session");
	return -1;
    }

  ctx->session = s;
  ctx->connected = 1;

  clib_warning ("HTTP PCAPng worker %u connected successfully",
		ctx->worker_index);
  return 0;
}

static void
http_pcapng_session_disconnect_callback (session_t *s)
{
  http_pcapng_ctx_t *ctx =
    (http_pcapng_ctx_t *) uword_to_pointer (s->opaque, http_pcapng_ctx_t *);

  if (ctx)
    {
	ctx->connected = 0;
	ctx->session = NULL;
	clib_warning ("HTTP PCAPng worker %u disconnected", ctx->worker_index);
    }
}

static void
http_pcapng_session_reset_callback (session_t *s)
{
  http_pcapng_session_disconnect_callback (s);
}

static int
http_pcapng_rx_callback (session_t *s)
{
  /* For POST uploads, we typically don't expect much response data
   * Just consume and log any response */
  u32 max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (max_deq > 0)
    {
	u8 *response_data = clib_mem_alloc (max_deq);
	if (response_data)
	  {
	    svm_fifo_dequeue (s->rx_fifo, max_deq, response_data);
	    clib_warning ("HTTP PCAPng received %u bytes response", max_deq);
	    clib_mem_free (response_data);
	  }
    }
  return 0;
}

static int
http_pcapng_tx_callback (session_t *s)
{
  /* Handle any pending transmission if needed */
  return 0;
}

/*******
 * GZ file utilities
 ******/
/**
 * Initialize a new PCAPNG gzip writer
 *
 * @param filename The output filename to write to
 * @return A pointer to the initialized writer or NULL on error
 */
void* pcapng_gzip_start(u32 worker_index) {
    gzfile_output_ctx_t *ctx;
    char filename[256];
  
  ctx = clib_mem_alloc_aligned (sizeof (gzfile_output_ctx_t), CLIB_CACHE_LINE_BYTES);
  memset (ctx, 0, sizeof (*ctx));

  /* Create a unique filename per worker */
  snprintf (filename, sizeof (filename), "/tmp/geneve_capture_worker%u.pcapng.gz", worker_index);
  ctx->filename = (void *)format (0, "%s%c", filename, 0);

    if (!ctx) {
        return NULL;
    }

    // Open the file with appropriate flags for syncing
    int fd = open(ctx->filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        clib_mem_free(ctx);
        return NULL;
    }

    // Open the gzip file with file descriptor
    gzFile gz_file = gzdopen(fd, "wb");
    if (!gz_file) {
        close(fd);
        clib_mem_free(ctx);
        return NULL;
    }

    // Set buffer size to 0 to make gzwrite flush immediately
    // This ensures file is always in a valid state
    // gzbuffer(gz_file, 0);

    ctx->gz_file = gz_file;
    ctx->fd = fd;

    return ctx;
}

/**
 * Write a chunk of PCAPNG data to the gzipped file
 *
 * @param writer The writer to use
 * @param chunk The chunk data to write
 * @param chunk_size The size of the chunk in bytes
 * @return 0 on success, -1 on error
 */
int pcapng_gzip_write_chunk(void *context, const void *chunk, size_t chunk_size) {
    gzfile_output_ctx_t *writer = context;
    if (!writer || !writer->gz_file) {
        return -1;
    }

    // Write the chunk
    int bytes_written = gzwrite(writer->gz_file, chunk, chunk_size);
    if (bytes_written != chunk_size) {
        return -1;
    }
    return 0;
}

static void
pcapng_gzip_flush(void *context) {
// Explicitly flush to ensure file is in a valid state

/*
    gzfile_output_ctx_t *writer = context;
    if (gzflush(writer->gz_file, Z_SYNC_FLUSH) != Z_OK) {
        return;
    }

    // Force a sync to disk
    fsync(writer->fd);
    */
}

/**
 * Close the gzip writer and free resources
 *
 * @param writer The writer to close
 * @return 0 on success, -1 on error
 */
static void pcapng_gzip_finish(void *context) {
    gzfile_output_ctx_t *writer = context;
    if (!writer) {
        return;
    }

    // Close the gzip file (which also flushes)
    if (gzclose(writer->gz_file) != Z_OK) {
        clib_warning("Could not call gzclose");
    }

    // Free resources
    clib_mem_free(writer->filename);
    clib_mem_free(writer);

    return;
}

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

static int
file_chunk_write (void *context, const void *chunk, size_t chunk_size)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  if (!ctx->file) {
      return -1;
  }
  int result = fwrite (chunk, 1, chunk_size, ctx->file) == chunk_size ? 0 : -1;
  return result;
}

static void
file_output_flush (void *context)
{
  file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  ASSERT(ctx->file);
  fflush (ctx->file);  /* Ensure data is written to disk */
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
file_write_pcapng_shb (geneve_output_t *out, void *context)
{
  // file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  struct {
    u32 block_type;
    u32 block_len;
    u32 magic;
    u16 major_version;
    u16 minor_version;
    u64 section_len;
    u32 block_len_copy;
  } __attribute__ ((packed)) shb;
  
  if (!context)
    return -1;
    
  memset (&shb, 0, sizeof (shb));
  shb.block_type = PCAPNG_BLOCK_TYPE_SHB;
  shb.block_len = sizeof (shb);
  shb.magic = 0x1A2B3C4D;  /* Byte order magic */
  shb.major_version = 1;
  shb.minor_version = 0;
  shb.section_len = 0xFFFFFFFFFFFFFFFF;  /* Unknown length */
  shb.block_len_copy = sizeof (shb);
  
  return out->chunk_write(context, &shb, sizeof (shb));
}

static int
file_write_pcapng_idb (geneve_output_t *out, void *context, u32 if_index, const char *if_name)
{
  // file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  u32 name_len, pad_len, total_len;
  u8 *block;
  int result;
  
  if (!context)
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
  // result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  result = out->chunk_write(context, block, total_len);
  
  clib_mem_free (block);
  return result;
}

static int
file_write_pcapng_epb (geneve_output_t *out, void *context, u32 if_index, u64 timestamp,
                       u32 orig_len, void *packet_data, u32 packet_len)
{
  // file_output_ctx_t *ctx = (file_output_ctx_t *) context;
  u32 pad_len, total_len;
  u8 *block;
  int result;
  
  if (!context)
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
  // result = fwrite (block, 1, total_len, ctx->file) == total_len ? 0 : -1;
  result = out->chunk_write(context, block, total_len);

  
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

/* Function to check if a packet matches a 5-tuple filter */
static bool
packet_matches_tuple_filter (const u8 *packet_data, u32 packet_len, 
                            const geneve_tuple_filter_t *filter)
{
  u32 i;
  
  /* Make sure we have enough data */
  if (packet_len < filter->length)
    return false;
    
  /* Apply mask and compare values */
  for (i = 0; i < filter->length; i++)
    {
      if ((packet_data[i] & filter->mask[i]) != (filter->value[i] & filter->mask[i]))
        goto no_match;
    }
    
  return true;
no_match:
  /*
    clib_warning("pkt: %U", format_hexdump, packet_data, packet_len);
    clib_warning("dat: %U", format_hexdump, filter->value, vec_len(filter->value));
    clib_warning("msk: %U", format_hexdump, filter->mask, vec_len(filter->mask));
  */
  return false;
}

/* Check if packet matches a Geneve filter */
static bool
geneve_packet_matches_filter (geneve_pcapng_main_t *gpm,
                             const u8 *outer_hdr, u32 outer_len,
                             const u8 *inner_hdr, u32 inner_len,
                             const geneve_header_t *geneve_hdr,
                             u32 geneve_header_len,
                             const geneve_capture_filter_t *filter)
{
  const geneve_option_t *opt;
  u32 remaining_len;
  int i;

  /* Check basic Geneve header fields if specified in filter */
  if (filter->ver_present && filter->ver != geneve_get_version (geneve_hdr))
    return false;
    
  if (filter->opt_len_present && filter->opt_len != geneve_get_opt_len (geneve_hdr))
    return false;
    
  if (filter->proto_present && filter->protocol != clib_net_to_host_u16 (geneve_hdr->protocol))
    return false;
    
  if (filter->vni_present && filter->vni != geneve_get_vni (geneve_hdr))
    return false;
    
  /* Check 5-tuple filters */
  if (filter->outer_tuple_present && 
      !packet_matches_tuple_filter (outer_hdr, outer_len, &filter->outer_tuple)) {
    return false;
  }
    
  if (filter->inner_tuple_present && 
      !packet_matches_tuple_filter (inner_hdr, inner_len, &filter->inner_tuple))
    return false;
  
  /* No option filters, match just on basic headers and tuples */
  if (vec_len (filter->option_filters) == 0)
    return true;

  /* Start of options */
  opt = (const geneve_option_t *)(geneve_hdr + 1);
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

/* Check if the packet matches any global filter */
static bool
matches_global_filters (geneve_pcapng_main_t *gpm,
                       const u8 *outer_hdr, u32 outer_len,
                       const u8 *inner_hdr, u32 inner_len,
                       const geneve_header_t *geneve_hdr,
                       u32 geneve_header_len)
{
  int i;
  
  /* Check each global filter */
  for (i = 0; i < vec_len (gpm->global_filters); i++)
    {
      if (geneve_packet_matches_filter (gpm, 
                                      outer_hdr, outer_len,
                                      inner_hdr, inner_len,
                                      geneve_hdr, geneve_header_len,
                                      &gpm->global_filters[i]))
        return true;
    }
    
  return false;
}

/* Extract inner IP header from packet */
static u8 *
get_inner_ip_header (const geneve_header_t *geneve_hdr, u32 geneve_header_len,
                    u32 *inner_len)
{
  u8 *inner_hdr;
  
  /* Calculate inner header pointer */
  inner_hdr = (u8 *)(geneve_hdr) + geneve_header_len;
  
  /* Determine inner header length (simplified) */
  *inner_len = 60;  /* Conservative estimate */
  
  return inner_hdr;
}

typedef struct
{
  u64 elapsed;
  u32 sw_if_index;
} pcapng_capture_trace_t;

static u8 *
format_pcapng_capture_trace (u8 *s, va_list *args)
{
  // int i;
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pcapng_capture_trace_t *t = va_arg (*args, pcapng_capture_trace_t *);

  // u32 indent = format_get_indent (s);

  s = format (s, "PCAPNG: sw_if_index %d elapsed %ld", t->sw_if_index, t->elapsed);
  return s;
}



/* Filter and capture Geneve packets */
static_always_inline uword geneve_pcapng_node_common (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame, int is_output)
{

  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  u32 n_left_from, *from, *to_next;
  u32 n_left_to_next;
  u32 worker_index = vlib_get_thread_index ();
  void *output_ctx;
  u32 next_index;
  u32 n_captured = 0;
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
      gpm->output.write_pcapng_shb (&gpm->output, output_ctx);
      static u8 *if_name = 0;
      int i;
      // FIXME: retrieve the real interfaces
      for (i=0; i<5*2; i++) {
        vec_reset_length (if_name);
        if_name = format (if_name, "vpp-if-%d-%s%c", i/2, i % 2 ? "out" : "in", 0);
        gpm->output.write_pcapng_idb (&gpm->output, output_ctx, i, (char *)if_name);
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
	  u64 packet_start = clib_cpu_time_now();
          vlib_buffer_t *b0;
          u32 bi0, sw_if_index0, next0 = 0;
          ip4_header_t *ip4;
          ip6_header_t *ip6;
          ethernet_header_t *ether;
          udp_header_t *udp;
          geneve_header_t *geneve;
          // bool is_ip6;
          bool packet_captured = false;
          
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
	  // clib_warning("CAPTURE is_out: %d", is_output);
          
          /* Skip interfaces where capture is not enabled, 
             unless global filters are defined */
          if ((sw_if_index0 >= vec_len (gpm->per_interface) ||
              !gpm->per_interface[sw_if_index0].capture_enabled) &&
              vec_len (gpm->global_filters) == 0)
            {
              goto packet_done;
            }
          
          /* Parse either IPv4 or IPv6 header */
          ether = vlib_buffer_get_current (b0);
          ip4 = (ip4_header_t *) (ether+1);
          
          const u8 *outer_header = (const u8 *)ip4;
          u32 outer_header_len = sizeof(ip4_header_t);
          
          if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
            {
/* IPv4 */
              // is_ip6 = false;
              outer_header_len = (ip4->ip_version_and_header_length & 0x0F) * 4;
              
              /* Skip non-UDP packets */
              if (ip4->protocol != IP_PROTOCOL_UDP)
                goto packet_done;
                
              /* UDP header follows IPv4 header */
              udp = (udp_header_t *)((u8 *)ip4 + outer_header_len);
	      outer_header_len += sizeof(udp_header_t);
            }
          else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60)
            {
              /* IPv6 */
              // is_ip6 = true;
              ip6 = (ip6_header_t *)ip4;
              outer_header = (const u8 *)ip6;
              outer_header_len = sizeof(ip6_header_t);
              
              /* Skip non-UDP packets */
              if (ip6->protocol != IP_PROTOCOL_UDP)
                goto packet_done;
                
              /* UDP header follows IPv6 header */
              udp = (udp_header_t *)(ip6 + 1);
	      outer_header_len += sizeof(udp_header_t);
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
          
          /* Get inner header for inner 5-tuple filtering */
          u32 inner_header_len = 0;
          const u8 *inner_header = get_inner_ip_header(geneve, geneve_header_len, &inner_header_len);
          
          /* Check if packet matches any global filter */
          if (vec_len (gpm->global_filters) > 0 &&
              matches_global_filters (gpm, outer_header, outer_header_len,
                                    inner_header, inner_header_len,
                                    geneve, geneve_header_len))
            {
              /* Packet matches a global filter, capture it */
              packet_captured = true;
            }
          
          /* Check if the packet matches any per-interface filter */
          if (!packet_captured && 
              sw_if_index0 < vec_len (gpm->per_interface) && 
              gpm->per_interface[sw_if_index0].capture_enabled)
            {
              for (i = 0; i < vec_len (gpm->per_interface[sw_if_index0].filters); i++)
                {
                  if (geneve_packet_matches_filter (gpm, 
                                                 outer_header, outer_header_len,
                                                 inner_header, inner_header_len,
                                                 geneve, geneve_header_len,
                                                 &gpm->per_interface[sw_if_index0].filters[i]))
                    {
                      /* Packet matches, capture it */
                      packet_captured = true;
                      break;
                    }
                }
            }
            
          if (packet_captured)
            {
              /* Capture the matching packet */
              u64 timestamp = vlib_time_now (vm) * 1000000; 
              u32 orig_len = vlib_buffer_length_in_chain (vm, b0);
              vlib_buffer_t *buf_iter = b0;
              
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
              gpm->output.write_pcapng_epb (&gpm->output, output_ctx, (sw_if_index0 << 1) | is_output, 
                                         timestamp, orig_len, 
                                         packet_copy, offset);
                                         
              vec_free (packet_copy);
	      n_captured += 1;
            }
packet_done:
            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              pcapng_capture_trace_t *t =
              vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
	      t->elapsed = clib_cpu_time_now() - packet_start;
            }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  if (n_captured) {
      // gpm->output.flush(output_ctx);
  }
    
  return frame->n_vectors;
}

VLIB_NODE_FN (geneve_pcapng_node_out) (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame)
{
   return geneve_pcapng_node_common(vm, node, frame, 1);
}

VLIB_NODE_FN (geneve_pcapng_node_in) (vlib_main_t *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t *frame)
{
   return geneve_pcapng_node_common(vm, node, frame, 0);
}


/* Node registration */
vlib_node_registration_t geneve_pcapng_node_out;
vlib_node_registration_t geneve_pcapng_node_in;

VLIB_REGISTER_NODE (geneve_pcapng_node_out) = {
  .name = "geneve-pcapng-capture-out",
  .vector_size = sizeof (u32),
  .format_trace = format_pcapng_capture_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  // Specify next nodes if any
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (geneve_pcapng_node_in) = {
  .name = "geneve-pcapng-capture-in",
  .vector_size = sizeof (u32),
  .format_trace = format_pcapng_capture_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  // Specify next nodes if any
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VNET_FEATURE_INIT (geneve_pcapng_feature_out, static) = {
  .arc_name = "interface-output",
  .node_name = "geneve-pcapng-capture-out",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

VNET_FEATURE_INIT (geneve_pcapng_feature_in, static) = {
  .arc_name = "device-input",
  .node_name = "geneve-pcapng-capture-in",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};


/******************************************************************************
 * 5-tuple filter utilities
 ******************************************************************************/

/* Helper functions to parse and format 5-tuple filter data */

/* Convert network prefix to mask */
static void
prefix_to_mask(u8 *mask, u8 is_ipv6, int prefix_len)
{
  int i, bytes;
  
  bytes = is_ipv6 ? 16 : 4;
  
  for (i = 0; i < bytes; i++) {
    if (prefix_len >= 8) {
      mask[i] = 0xFF;
      prefix_len -= 8;
    } else if (prefix_len > 0) {
      mask[i] = (0xFF << (8 - prefix_len));
      prefix_len = 0;
    } else {
      mask[i] = 0;
    }
  }
}

/* Parse IPv4 address with optional prefix */
uword
parse_ipv4_prefix(unformat_input_t *input, va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  int offset = va_arg (*args, int);
  ip4_address_t ip4;
  int prefix_len = 32;

  if (unformat(input, "%U/%d", unformat_ip4_address, &ip4, &prefix_len)) {
    /* Address with prefix */
    if (prefix_len > 32) {
      clib_warning("IPv4 prefix length must be <= 32");
      return 0;
      }
  } else if (unformat(input, "%U", unformat_ip4_address, &ip4)) {
    /* Just the address */
  } else {
    clib_warning("Invalid IPv4 address format");
    return 0;
  }
  
  /* Allocate and set value */
  vec_validate(*value, offset+4-1);
  vec_validate(*mask, offset+4-1);
  memcpy(*value + offset, &ip4, 4);
  
  /* Create mask based on prefix length */
  prefix_to_mask(*mask+offset, 0, prefix_len);
  clib_warning("Parsed address: %U prefix len %d", format_ip4_address, &ip4, prefix_len);
  
  return 1;
}

/* Parse IPv6 address with optional prefix */
uword
parse_ipv6_prefix(unformat_input_t *input, va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  int offset = va_arg (*args, int);
  ip6_address_t ip6;
  u8 prefix_len = 128;
  
  if (unformat(input, "%U/%d", unformat_ip6_address, &ip6, &prefix_len)) {
    /* Address with prefix */
    if (prefix_len > 128) {
      clib_warning("IPv6 prefix length must be <= 128");
      return 0;
      }
  } else if (unformat(input, "%U", unformat_ip6_address, &ip6)) {
    /* Just the address */
  } else {
    clib_warning("Invalid IPv6 address format");
    return 0;
  }
  
  /* Allocate and set value */
  vec_validate(*value, offset + 16 - 1);
  vec_validate(*mask, offset + 16 - 1);
  memcpy(*value + offset, &ip6, 16);
  
  /* Create mask based on prefix length */
  prefix_to_mask(*mask + offset, 1, prefix_len);
  
  return 1;
}

/* Parse port number or range */
uword
parse_port(unformat_input_t *input, va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  uword offset = va_arg (*args, uword);

  u32 port_lo = 0;
  
  if (unformat(input, "%d", &port_lo)) {
    /* the port is two bytes */
    vec_validate(*value, offset+1);
    vec_validate(*mask, offset+1);
    clib_warning("Set offset %d to value %u", offset, port_lo);
    
    /* Store port in network byte order */
    port_lo = clib_host_to_net_u16(port_lo);
    memcpy(*value + offset, &port_lo, 2);
    
    /* Mask is all 1's for exact match */
    memset(*mask + offset, 0xFF, 2);
    
  } else {
    return 0;
  }
  
  return 1;
}

/* Parse protocol number */
uword
parse_protocol(unformat_input_t *input,  va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  int offset = va_arg (*args, int);
  clib_warning("protocol offset: %d", offset);
  u32 proto;
  
  if (unformat(input, "tcp")) {
    proto = IP_PROTOCOL_TCP;
  } else if (unformat(input, "udp")) {
    proto = IP_PROTOCOL_UDP;
  } else if (unformat(input, "icmp")) {
    proto = IP_PROTOCOL_ICMP;
  } else if (unformat(input, "icmp6")) {
    proto = IP_PROTOCOL_ICMP6;
  } else if (unformat(input, "%d", &proto)) {
    /* Direct protocol number */
  } else {
    return 0;
  }
  
  vec_validate(*value, offset);
  vec_validate(*mask, offset);
  
  (*value)[offset] = proto;
  (*mask)[offset] = 0xFF;  /* Exact match for protocol */
  
  return 1;
}

/* Parse a raw byte value in hex format */
static clib_error_t *
parse_hex_byte(unformat_input_t *input, u8 **value, u8 **mask, u8 offset, u8 len)
{
  u8 i, byte_val;
  
  vec_validate(*value, offset + len - 1);
  vec_validate(*mask, offset + len - 1);
  
  for (i = 0; i < len; i++) {
    if (!unformat(input, "%x", &byte_val)) {
      return clib_error_return(0, "Invalid hex byte format");
    }
    
    (*value)[offset + i] = byte_val;
    (*mask)[offset + i] = 0xFF;  /* Exact match for hex */
  }
  
  return 0;
}

#define IP4_SRC_IP_OFFSET 12
#define IP4_DST_IP_OFFSET 16
#define IP4_SRC_PORT_OFFSET 20
#define IP4_DST_PORT_OFFSET 22
#define IP4_PROTO_OFFSET 9

/* Create an IPv4 5-tuple filter */
static clib_error_t *
create_ipv4_5tuple_filter(unformat_input_t *input, geneve_tuple_filter_t *filter)
{
  clib_error_t *error = NULL;
  u8 *value = filter->value;
  u8 *mask = filter->mask;

  vec_validate(value, 0);
  vec_validate(mask, 0);

  value[0] = 0x40;
  mask[0] = 0xf0;
  
  /* Parse fields in any order */
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "src-ip %U", parse_ipv4_prefix, &value, &mask, IP4_SRC_IP_OFFSET)) {
      /* Source IP already parsed */
    } else if (unformat(input, "dst-ip %U", parse_ipv4_prefix, &value, &mask, IP4_DST_IP_OFFSET)) {
      /* Destination IP already parsed */
    } else if (unformat(input, "src-port %U", parse_port, &value, &mask, IP4_SRC_PORT_OFFSET)) {
      /* Source port already parsed */
    } else if (unformat(input, "dst-port %U", parse_port, &value, &mask, IP4_DST_PORT_OFFSET)) {
      /* Destination port already parsed */
    } else if (unformat(input, "proto %U", parse_protocol, &value, &mask, IP4_PROTO_OFFSET)) {
      /* Protocol already parsed */
    } else if (unformat(input, "raw %U", parse_hex_byte, &value, &mask, 0, vec_len(value))) {
      /* Raw hex value parsed */
    } else {
      error = clib_error_return(0, "Unknown input: %U", format_unformat_error, input);
      goto done;
    }
  }
  
  /* Store the results */
  filter->value = value;
  filter->mask = mask;
  filter->length = vec_len(value);
  
  return 0;
  
done:
  vec_free(value);
  vec_free(mask);
  return error;
}

#define IP6_SRC_IP_OFFSET 8
#define IP6_DST_IP_OFFSET 24
#define IP6_SRC_PORT_OFFSET 40
#define IP6_DST_PORT_OFFSET 42
#define IP6_PROTO_OFFSET 6

/* Create an IPv6 5-tuple filter */
static clib_error_t *
create_ipv6_5tuple_filter(unformat_input_t *input, geneve_tuple_filter_t *filter)
{
  clib_error_t *error = NULL;
  u8 *value = filter->value;
  u8 *mask = filter->mask;
  
  vec_validate(value, 0);
  vec_validate(mask, 0);
  
  /* Default mask is all 0's (don't care) */
  memset(mask, 0, vec_len(mask));

  /* IPv6 */
  value[0] = 0x60;
  mask[0] = 0xf0;

  
  /* Parse fields in any order */
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "src-ip %U", parse_ipv6_prefix, &value, &mask, IP6_SRC_IP_OFFSET)) {
      /* Source IP already parsed */
    } else if (unformat(input, "dst-ip %U", parse_ipv6_prefix, &value, &mask, IP6_DST_IP_OFFSET)) {
      /* Destination IP already parsed */
    } else if (unformat(input, "src-port %U", parse_port, &value, &mask, IP6_SRC_PORT_OFFSET)) {
      /* Source port already parsed */
    } else if (unformat(input, "dst-port %U", parse_port, &value, &mask, IP6_DST_PORT_OFFSET)) {
      /* Destination port already parsed */
    } else if (unformat(input, "proto %U", parse_protocol, &value, &mask, IP6_PROTO_OFFSET)) {
      /* Protocol already parsed */
    } else if (unformat(input, "raw %U", parse_hex_byte, &value, &mask, 0, vec_len(value))) {
      /* Raw hex value parsed */
    } else {
      error = clib_error_return(0, "Unknown input: %U", format_unformat_error, input);
      goto done;
    }
  }
  
  /* Store the results */
  filter->value = value;
  filter->mask = mask;
  filter->length = vec_len(value);
  
  return 0;
  
done:
  vec_free(value);
  vec_free(mask);
  return error;
}

/******************************************************************************
 * API and initialization
 ******************************************************************************/

static u32 random_seed = 42;

int
geneve_pcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter, u8 is_global)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  geneve_capture_filter_t *new_filter;
  u32 filter_id;
  
  /* For global filter, sw_if_index is ignored */
  if (!is_global) {
    /* Validate sw_if_index */
    if (sw_if_index == ~0)
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
      
    /* Ensure we have space for this interface */
    vec_validate (gpm->per_interface, sw_if_index);
  }
  
  /* Generate a unique filter ID */
  filter_id = random_u32(&random_seed);
  
  /* Add the filter to the appropriate list */
  if (is_global) {
    vec_add2 (gpm->global_filters, new_filter, 1);
  } else {
    vec_add2 (gpm->per_interface[sw_if_index].filters, new_filter, 1);
  }
  
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
                                 CLIB_CACHE_LINE_BYTES);
            }
            
          if (filter->option_filters[i].mask)
            {
              new_filter->option_filters[i].mask = 
                vec_dup_aligned (filter->option_filters[i].mask,
                                 CLIB_CACHE_LINE_BYTES);
            }
        }
    }
    
  /* Copy 5-tuple filters */
  if (filter->outer_tuple_present)
    {
      new_filter->outer_tuple_present = 1;
      new_filter->outer_tuple.value = vec_dup (filter->outer_tuple.value);
      new_filter->outer_tuple.mask = vec_dup (filter->outer_tuple.mask);
      new_filter->outer_tuple.length = filter->outer_tuple.length;
    }
    
  if (filter->inner_tuple_present)
    {
      new_filter->inner_tuple_present = 1;
      new_filter->inner_tuple.value = vec_dup (filter->inner_tuple.value);
      new_filter->inner_tuple.mask = vec_dup (filter->inner_tuple.mask);
      new_filter->inner_tuple.length = filter->inner_tuple.length;
    }
    
  return filter_id;
}

int
geneve_pcapng_del_filter (u32 sw_if_index, u32 filter_id, u8 is_global)
{
  geneve_pcapng_main_t *gpm = &geneve_pcapng_main;
  geneve_capture_filter_t *filters;
  int i;
  
  /* Select filter list based on scope */
  if (is_global) {
    filters = gpm->global_filters;
  } else {
    /* Check interface exists */
    if (sw_if_index >= vec_len(gpm->per_interface))
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
      
    filters = gpm->per_interface[sw_if_index].filters;
  }
  
  /* Find and remove the filter with matching ID */
  for (i = 0; i < vec_len(filters); i++) {
    if (filters[i].filter_id == filter_id) {
      /* Cleanup option filters */
      if (filters[i].option_filters) {
        int j;
        for (j = 0; j < vec_len(filters[i].option_filters); j++) {
          if (filters[i].option_filters[j].option_name)
            vec_free (filters[i].option_filters[j].option_name);
          if (filters[i].option_filters[j].data)
            vec_free (filters[i].option_filters[j].data);
          if (filters[i].option_filters[j].mask)
            vec_free (filters[i].option_filters[j].mask);
        }
        vec_free (filters[i].option_filters);
      }
      
      /* Cleanup 5-tuple filters */
      if (filters[i].outer_tuple_present) {
        vec_free (filters[i].outer_tuple.value);
        vec_free (filters[i].outer_tuple.mask);
      }
      
      if (filters[i].inner_tuple_present) {
        vec_free (filters[i].inner_tuple.value);
        vec_free (filters[i].inner_tuple.mask);
      }
      
      /* Remove the filter from the vector */
      if (is_global) {
        vec_delete (gpm->global_filters, 1, i);
      } else {
        vec_delete (gpm->per_interface[sw_if_index].filters, 1, i);
      }
      
      return 0;
    }
  }
  
  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
geneve_pcapng_enable_capture (u32 sw_if_index, u8 enable)
{
  geneve_pcapng_main_t *gmp = &geneve_pcapng_main;
  vnet_main_t *vnm = vnet_get_main ();

  /* Validate interface index */
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Ensure we have storage for this interface */
  vec_validate (gmp->per_interface, sw_if_index);

  /* Update the enabled state */
  gmp->per_interface[sw_if_index].capture_enabled = enable;

  if (enable)
    {
      /* Enable the feature on this interface */
      vnet_feature_enable_disable ("interface-output", "geneve-pcapng-capture-out",
                                   sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("device-input", "geneve-pcapng-capture-in",
                                   sw_if_index, 1, 0, 0);
    }
  else
    {
      /* Disable the feature on this interface */
      vnet_feature_enable_disable ("interface-output", "geneve-pcapng-capture-out",
                                   sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("device-input", "geneve-pcapng-capture-in",
                                   sw_if_index, 0, 0, 0);
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

typedef enum {
   TUPLE_FILTER_UNKNOWN = 0,
   TUPLE_FILTER_IP4,
   TUPLE_FILTER_IP6,
} tuple_filter_t; 

/* Format a 5-tuple filter for display */
static u8 *
format_tuple_filter (u8 *s, va_list *args)
{
  geneve_tuple_filter_t *filter = va_arg (*args, geneve_tuple_filter_t *);
  int i;
  
  /* Display raw hex values first */
  s = format (s, "        Data bytes (%d): ", vec_len(filter->value));
  for (i = 0; i < vec_len(filter->value); i++)
    {
      s = format (s, "%02x", filter->value[i]);
      if (i < vec_len(filter->value) - 1)
        s = format (s, " ");
    }
  s = format (s, "\n");
  
  s = format (s, "        Mask bytes (%d): ", vec_len(filter->mask));
  for (i = 0; i < vec_len(filter->mask); i++)
    {
      s = format (s, "%02x", filter->mask[i]);
      if (i < vec_len(filter->mask) - 1)
        s = format (s, " ");
    }
  s = format (s, "\n");
  
  /* Try to interpret fields in a meaningful way */
  /* Protocol */
  int proto_offset = 0; /* should be reset from 0 */
  int src_port_offset = 0;
  int dst_port_offset = 0;

  tuple_filter_t filter_type = TUPLE_FILTER_UNKNOWN;
  if (filter->length > 0 && filter->mask[0])
    {
      s = format (s, "       ");
      switch (filter->value[0] & 0xf0) {
         case 0x40:
             s = format (s, "IPv4:\n");
	     proto_offset = IP4_PROTO_OFFSET;
	     src_port_offset = IP4_SRC_PORT_OFFSET;
	     dst_port_offset = IP4_DST_PORT_OFFSET;
	     filter_type = TUPLE_FILTER_IP4;
	     break;
	 case 0x60:
             s = format (s, "IPv6:\n");
	     proto_offset = IP6_PROTO_OFFSET;
	     src_port_offset = IP6_SRC_PORT_OFFSET;
	     dst_port_offset = IP6_DST_PORT_OFFSET;
	     filter_type = TUPLE_FILTER_IP6;
	     break;
      }
    }

  
  /* IP addresses - offset and format based on IPv4 or IPv6 */
  switch (filter_type) {
    case TUPLE_FILTER_IP6:
    {
      /* IPv6 source address (bytes 1-16) */
      u8 has_src_ip = 0;
      for (i = 0; i < 16; i++)
        {
          if (filter->mask[i + IP6_SRC_IP_OFFSET])
            {
              has_src_ip = 1;
              break;
            }
        }
      
      if (has_src_ip)
        {
          ip6_address_t src_ip;
          memcpy (&src_ip, filter->value + IP6_SRC_IP_OFFSET, 16);
          s = format (s, "       Src IP: %U", format_ip6_address, &src_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 128;
          for (i = 0; i < 16; i++)
            {
              if (filter->mask[i + IP6_SRC_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP6_SRC_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + 1];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 128)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
      
      /* IPv6 destination address (bytes 17-32) */
      u8 has_dst_ip = 0;
      for (i = 0; i < 16; i++)
        {
          if (filter->mask[i + IP6_DST_IP_OFFSET])
            {
              has_dst_ip = 1;
              break;
            }
        }
      
      if (has_dst_ip)
        {
          ip6_address_t dst_ip;
          memcpy (&dst_ip, filter->value + IP6_DST_IP_OFFSET, 16);
          s = format (s, "       Dst IP: %U", format_ip6_address, &dst_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 128;
          for (i = 0; i < 16; i++)
            {
              if (filter->mask[i + IP6_DST_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP6_DST_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + IP6_DST_IP_OFFSET];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 128)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
      
    }
    break;
  case TUPLE_FILTER_IP4:
    {
      /* IPv4 source address (bytes 1-4) */
      u8 has_src_ip = 0;
      for (i = 0; i < 4; i++)
        {
          if (filter->mask[i + IP4_SRC_IP_OFFSET])
            {
              has_src_ip = 1;
              break;
            }
        }
      
      if (has_src_ip)
        {
          ip4_address_t src_ip;
          memcpy (&src_ip, filter->value + IP4_SRC_IP_OFFSET, 4);
          s = format (s, "      Src IP: %U", format_ip4_address, &src_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 32;
          for (i = 0; i < 4; i++)
            {
              if (filter->mask[i + IP4_SRC_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP4_SRC_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + IP4_SRC_IP_OFFSET];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 32)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
      
      /* IPv4 destination address (bytes 5-8) */
      u8 has_dst_ip = 0;
      for (i = 0; i < 4; i++)
        {
          if (filter->mask[i + IP4_DST_IP_OFFSET])
            {
              has_dst_ip = 1;
              break;
            }
        }
      
      if (has_dst_ip)
        {
          ip4_address_t dst_ip;
          memcpy (&dst_ip, filter->value + IP4_DST_IP_OFFSET, 4);
          s = format (s, "       Dst IP: %U", format_ip4_address, &dst_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 32;
          for (i = 0; i < 4; i++)
            {
              if (filter->mask[i + IP4_DST_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP4_DST_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + IP4_DST_IP_OFFSET];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 32)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
    }
    break;
  default:
     /* no IP addresses */
     break;
  }

  if (filter->length > proto_offset  && proto_offset && filter->mask[proto_offset])
    {
      u8 proto = filter->value[proto_offset];
      s = format (s, "       Protocol: ");
      if (proto == IP_PROTOCOL_TCP)
        s = format (s, "TCP (6)\n");
      else if (proto == IP_PROTOCOL_UDP)
        s = format (s, "UDP (17)\n");
      else if (proto == IP_PROTOCOL_ICMP)
        s = format (s, "ICMP (1)\n");
      else if (proto == IP_PROTOCOL_ICMP6)
        s = format (s, "ICMPv6 (58)\n");
      else
        s = format (s, "0x%x (mask 0x%x)\n", proto, filter->mask[proto_offset]);

      /* Ports */
      if (filter->length > src_port_offset+1 && (filter->mask[src_port_offset] || filter->mask[src_port_offset+1]))
        {
          u16 src_port = 0;
          memcpy (&src_port, filter->value + src_port_offset, 2);
          src_port = clib_net_to_host_u16 (src_port);
          s = format (s, "         Src Port(%d): %d\n", src_port_offset, src_port);
        }
      
      if (filter->length > dst_port_offset+1 && (filter->mask[dst_port_offset] || filter->mask[dst_port_offset+1]))
        {
          u16 dst_port = 0;
          memcpy (&dst_port, filter->value + dst_port_offset, 2);
          dst_port = clib_net_to_host_u16 (dst_port);
          s = format (s, "         Dst Port(%d): %d\n", dst_port_offset, dst_port);
        }
    }
  
  return s;
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
  u8 is_global = 0;
  u32 filter_id = ~0;
  char * option_name = 0;
  unformat_input_t sub_input;
  enable_session_manager (vm);

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");
    
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U",
                   unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else if (unformat (line_input, "global"))
        is_global = 1;
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
      else if (unformat (line_input, "outer-ipv4 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv4_5tuple_filter(&sub_input, &filter.outer_tuple);
	  if (error)
	  	goto done;
          filter.outer_tuple_present = 1;
        }
      else if (unformat (line_input, "outer-ipv6 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv6_5tuple_filter(&sub_input, &filter.outer_tuple);
	  if (error)
	  	goto done;
          filter.outer_tuple_present = 1;
        }
      else if (unformat (line_input, "inner-ipv4 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv4_5tuple_filter(&sub_input, &filter.inner_tuple);
	  if (error)
	  	goto done;
          filter.inner_tuple_present = 1;
        }
      else if (unformat (line_input, "inner-ipv6 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv6_5tuple_filter(&sub_input, &filter.inner_tuple);
	  if (error)
	  	goto done;
          filter.inner_tuple_present = 1;
        }
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
          else
            {
              /* Option is not registered, handle raw data */
              if (unformat (line_input, "any"))
                {
                  opt_filter.match_any = 1;
                }
              else if (unformat (line_input, "length %d", &opt_filter.data_len))
                {
                  if (unformat (line_input, "value"))
                    {
                      error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
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
              else
                {
                  /* No length specified, default to match any */
                  opt_filter.match_any = 1;
                }
            }
            
          /* Add the option filter to the vector */
          vec_add1 (filter.option_filters, opt_filter);
        }
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }
    
  /* Validate inputs */
  if (!is_global && sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface required for interface filter");
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
      filter_id = geneve_pcapng_add_filter (sw_if_index, &filter, is_global);
      if (filter_id < 0)
        {
          error = clib_error_return (0, "failed to add filter");
          goto done;
        }
        
      vlib_cli_output (vm, "Added GENEVE %s filter with ID: %d", 
                      is_global ? "global" : "interface", filter_id);
    }
  else
    {
      int rv = geneve_pcapng_del_filter (sw_if_index, filter_id, is_global);
      if (rv < 0)
        {
          error = clib_error_return (0, "failed to delete filter (id: %d)", filter_id);
          goto done;
        }
        
      vlib_cli_output (vm, "Deleted GENEVE %s filter with ID: %d", 
                      is_global ? "global" : "interface", filter_id);
    }
    
done:
  /* Cleanup if error */
  if (error && is_add)
    {
      /* Clean up filter resources */
      if (filter.option_filters)
        {
          int i;
          for (i = 0; i < vec_len (filter.option_filters); i++)
            {
              if (filter.option_filters[i].option_name)
                vec_free (filter.option_filters[i].option_name);
              if (filter.option_filters[i].data)
                vec_free (filter.option_filters[i].data);
              if (filter.option_filters[i].mask)
                vec_free (filter.option_filters[i].mask);
            }
          vec_free (filter.option_filters);
        }
        
      if (filter.outer_tuple_present)
        {
          vec_free (filter.outer_tuple.value);
          vec_free (filter.outer_tuple.mask);
        }
        
      if (filter.inner_tuple_present)
        {
          vec_free (filter.inner_tuple.value);
          vec_free (filter.inner_tuple.mask);
        }
    }
    
  unformat_free (line_input);
  return error;
}

/* Updated CLI command for better help text */
VLIB_CLI_COMMAND (geneve_pcapng_filter_command, static) = {
  .path = "geneve pcapng filter",
  .short_help = "geneve pcapng filter [interface <interface> | global] "
                "[ver <ver>] [opt-len <len>] [protocol <proto>] [vni <vni>] "
                "[outer-ipv4 | outer-ipv6 | inner-ipv4 | inner-ipv6] "
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
  if (vec_len (gpm->global_filters) > 0)
    {
      vlib_cli_output (vm, "\nGlobal Filters:");
      
      for (i = 0; i < vec_len (gpm->global_filters); i++)
        {
          geneve_capture_filter_t *filter = &gpm->global_filters[i];
          
          vlib_cli_output (vm, "  Filter ID: %u", filter->filter_id);
          
          /* Basic header filters */
          if (filter->ver_present)
            vlib_cli_output (vm, "    Version: %u", filter->ver);
            
          if (filter->opt_len_present)
            vlib_cli_output (vm, "    Option Length: %u", filter->opt_len);
            
          if (filter->proto_present)
            vlib_cli_output (vm, "    Protocol: 0x%04x", filter->protocol);
            
          if (filter->vni_present)
            vlib_cli_output (vm, "    VNI: %u", filter->vni);
            
          /* 5-tuple filters */
          if (filter->outer_tuple_present)
            {
              vlib_cli_output (vm, "    Outer 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->outer_tuple, 
                             filter->outer_tuple.length > 20); /* is_ipv6 */
            }
            
          if (filter->inner_tuple_present)
            {
              vlib_cli_output (vm, "    Inner 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->inner_tuple,
                             filter->inner_tuple.length > 20); /* is_ipv6 */
            }
            
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
  
  /* Display per-interface filters */
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
          
          /* Basic header filters */
          if (filter->ver_present)
            vlib_cli_output (vm, "    Version: %u", filter->ver);
            
          if (filter->opt_len_present)
            vlib_cli_output (vm, "    Option Length: %u", filter->opt_len);
            
          if (filter->proto_present)
            vlib_cli_output (vm, "    Protocol: 0x%04x", filter->protocol);
            
          if (filter->vni_present)
            vlib_cli_output (vm, "    VNI: %u", filter->vni);
            
          /* 5-tuple filters */
          if (filter->outer_tuple_present)
            {
              vlib_cli_output (vm, "    Outer 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->outer_tuple, 
                             filter->outer_tuple.length > 20); /* is_ipv6 */
            }
            
          if (filter->inner_tuple_present)
            {
              vlib_cli_output (vm, "    Inner 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->inner_tuple,
                             filter->inner_tuple.length > 20); /* is_ipv6 */
            }
            
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
  gpm->output.chunk_write = file_chunk_write;
  gpm->output.flush = file_output_flush;

  gpm->output.init = pcapng_gzip_start;
  gpm->output.cleanup = pcapng_gzip_finish;
  gpm->output.chunk_write = pcapng_gzip_write_chunk;
  gpm->output.flush = pcapng_gzip_flush;

  gpm->output.init = pcapng_igzip_start;
  gpm->output.cleanup = pcapng_igzip_finish;
  gpm->output.chunk_write = pcapng_igzip_write_chunk;
  gpm->output.flush = pcapng_igzip_flush;

  // final result
  gpm->output.init = pcapng_igzip_start;
  gpm->output.cleanup = pcapng_igzip_finish;
  gpm->output.chunk_write = pcapng_igzip_write_chunk;
  gpm->output.flush = pcapng_igzip_flush;

  // final result for http
  gpm->output.init = http_pcapng_init;
  gpm->output.flush = http_pcapng_flush;
  gpm->output.chunk_write = http_pcapng_chunk_write;
  gpm->output.cleanup = http_pcapng_cleanup;

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

  /* Initialize the global filter vector */
  gpm->global_filters = 0; /* Empty vector */

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
