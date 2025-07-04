/*
 * Copyright (c) 2017-2022 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <http_static/http_static.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <http_static/http_static.api_enum.h>
#include <http_static/http_static.api_types.h>

#include <vpp/api/types.h>


#define REPLY_MSG_ID_BASE hsm->msg_id_base
#include <vlibapi/api_helper_macros.h>

__clib_export void
hss_register_url_handler (hss_url_handler_fn fp, const char *url,
			  http_req_method_t request_type)
{
  hss_main_t *hsm = &hss_main;
  uword *p, *url_table;

  url_table = (request_type == HTTP_REQ_GET) ? hsm->get_url_handlers :
					       hsm->post_url_handlers;

  p = hash_get_mem (url_table, url);

  if (p)
    {
      clib_warning ("WARNING: attempt to replace handler for %s '%s' ignored",
		    (request_type == HTTP_REQ_GET) ? "GET" : "POST", url);
      return;
    }

  hash_set_mem (url_table, url, (uword) fp);

  /*
   * Need to update the hash table pointer in http_static_server_main
   * in case we just expanded it...
   */
  if (request_type == HTTP_REQ_GET)
    hsm->get_url_handlers = url_table;
  else
    hsm->post_url_handlers = url_table;
}

/** \brief API helper function for vl_api_http_static_enable_t messages
 */
static int
hss_enable_api (u32 fifo_size, u32 cache_limit, u32 prealloc_fifos,
		u32 private_segment_size, u8 *www_root, u8 *uri, u32 max_age,
		u32 keepalive_timeout, u64 max_body_size, u32 rx_buff_thresh)
{
  hss_main_t *hsm = &hss_main;
  int rv;

  hsm->fifo_size = fifo_size;
  hsm->prealloc_fifos = prealloc_fifos;
  hsm->private_segment_size = private_segment_size;
  if (uri && parse_uri ((char *) uri, &hsm->default_listener.sep))
    return VNET_API_ERROR_INVALID_VALUE;
  hsm->default_listener.www_root = format (0, "%s%c", www_root, 0);
  hsm->default_listener.cache_size = cache_limit;
  hsm->default_listener.max_age = max_age;
  hsm->default_listener.max_req_body_size = max_body_size;
  hsm->default_listener.rx_buff_thresh = rx_buff_thresh;
  hsm->default_listener.keepalive_timeout = keepalive_timeout;
  hsm->have_default_listener = 1;

  if (vec_len (hsm->default_listener.www_root) < 2)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hsm->app_index != ~0)
    return VNET_API_ERROR_APP_ALREADY_ATTACHED;

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (hsm->vlib_main, &args);

  rv = hss_create (hsm->vlib_main);
  switch (rv)
    {
    case 0:
      break;
    default:
      vec_free (hsm->default_listener.www_root);
      return VNET_API_ERROR_INIT_FAILED;
    }
  return 0;
}

/* API message handler */
static void
vl_api_http_static_enable_v4_t_handler (vl_api_http_static_enable_v4_t *mp)
{
  vl_api_http_static_enable_v4_reply_t *rmp;
  hss_main_t *hsm = &hss_main;
  int rv;

  mp->uri[ARRAY_LEN (mp->uri) - 1] = 0;
  mp->www_root[ARRAY_LEN (mp->www_root) - 1] = 0;

  rv = hss_enable_api (
    ntohl (mp->fifo_size), ntohl (mp->cache_size_limit),
    ntohl (mp->prealloc_fifos), ntohl (mp->private_segment_size), mp->www_root,
    mp->uri, ntohl (mp->max_age), ntohl (mp->keepalive_timeout),
    ntohl (mp->max_body_size), HSS_DEFAULT_RX_BUFFER_THRESH);

  REPLY_MACRO (VL_API_HTTP_STATIC_ENABLE_V4_REPLY);
}

/* API message handler */
static void
vl_api_http_static_enable_v5_t_handler (vl_api_http_static_enable_v5_t *mp)
{
  vl_api_http_static_enable_v5_reply_t *rmp;
  hss_main_t *hsm = &hss_main;
  int rv;

  mp->uri[ARRAY_LEN (mp->uri) - 1] = 0;
  mp->www_root[ARRAY_LEN (mp->www_root) - 1] = 0;

  rv = hss_enable_api (ntohl (mp->fifo_size), ntohl (mp->cache_size_limit),
		       ntohl (mp->prealloc_fifos),
		       ntohl (mp->private_segment_size), mp->www_root, mp->uri,
		       ntohl (mp->max_age), ntohl (mp->keepalive_timeout),
		       ntohl (mp->max_body_size), ntohl (mp->rx_buff_thresh));

  REPLY_MACRO (VL_API_HTTP_STATIC_ENABLE_V5_REPLY);
}

#include <http_static/http_static.api.c>
static clib_error_t *
hss_api_init (vlib_main_t *vm)
{
  hss_main_t *hsm = &hss_main;

  /* Ask for a correctly-sized block of API message decode slots */
  hsm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (hss_api_init);

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "HTTP Static Server"
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
