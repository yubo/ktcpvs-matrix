#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

#undef unix
struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = __stringify(KBUILD_MODNAME),
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0x65b4e613, "struct_module" },
	{ 0x7da8156e, "__kmalloc" },
	{ 0x1d42aeb5, "sysctl_ktcpvs_keepalive_timeout" },
	{ 0xae407716, "tcp_vs_del_slowtimer" },
	{ 0xf39cc429, "tcp_vs_srvconn_get" },
	{ 0x6c3397fb, "malloc_sizes" },
	{ 0xc045a20c, "remove_wait_queue" },
	{ 0x8cedd42e, "register_tcp_vs_scheduler" },
	{ 0x4e830a3e, "strnicmp" },
	{ 0x6431e631, "tcp_vs_recvbuffer" },
	{ 0x1d26aa98, "sprintf" },
	{ 0x99a4bdb6, "unregister_tcp_vs_scheduler" },
	{ 0xda02d67, "jiffies" },
	{ 0xa26ce134, "default_wake_function" },
	{ 0x8d3894f2, "_ctype" },
	{ 0x1b7d4074, "printk" },
	{ 0x859204af, "sscanf" },
	{ 0x71c90087, "memcmp" },
	{ 0x1075bf0, "panic" },
	{ 0x40abbb36, "tcp_vs_srvconn_put" },
	{ 0x23c07319, "tcp_vs_xmit" },
	{ 0xd8a49826, "sysctl_ktcpvs_unload" },
	{ 0xc161af80, "tcp_vs_add_slowtimer" },
	{ 0x123d3b6a, "kmem_cache_alloc" },
	{ 0xb2ed2746, "tcp_vs_srvconn_new" },
	{ 0x4784e424, "__get_free_pages" },
	{ 0x17d59d01, "schedule_timeout" },
	{ 0x4292364c, "schedule" },
	{ 0x76bdade9, "tcp_vs_srvconn_free" },
	{ 0x9941ccb8, "free_pages" },
	{ 0x29a04e4e, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xdf20e9c, "interruptible_sleep_on_timeout" },
	{ 0x25da070, "snprintf" },
	{ 0x8235805b, "memmove" },
	{ 0xeded259a, "tcp_vs_get_debug_level" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=ktcpvs";

