use ash::{vk, Entry};
use std::ffi::{c_char, CStr};

unsafe extern "system" fn vulkan_debug_utils_callback(
    message_severity: vk::DebugUtilsMessageSeverityFlagsEXT,
    message_type: vk::DebugUtilsMessageTypeFlagsEXT,
    p_callback_data: *const vk::DebugUtilsMessengerCallbackDataEXT,
    _p_user_data: *mut std::ffi::c_void,
) -> vk::Bool32 {
    let message = CStr::from_ptr((*p_callback_data).p_message);
    let severity = format!("{:?}", message_severity).to_lowercase();
    let ty = format!("{:?}", message_type).to_lowercase();
    println!("[Debug][{}][{}] {:?}", severity, ty, message);
    vk::FALSE
}

fn main() {
    let app_name = c"Vulkan Test App";
    let app_info = vk::ApplicationInfo::default()
        .application_name(app_name)
        .application_version(0)
        .engine_name(app_name)
        .engine_version(0)
        .api_version(vk::make_api_version(0, 1, 0, 0));

    let mut debugcreateinfo = vk::DebugUtilsMessengerCreateInfoEXT::default()
        .message_severity(
            vk::DebugUtilsMessageSeverityFlagsEXT::WARNING
                | vk::DebugUtilsMessageSeverityFlagsEXT::VERBOSE
                | vk::DebugUtilsMessageSeverityFlagsEXT::INFO
                | vk::DebugUtilsMessageSeverityFlagsEXT::ERROR,
        )
        .message_type(
            vk::DebugUtilsMessageTypeFlagsEXT::GENERAL
                | vk::DebugUtilsMessageTypeFlagsEXT::PERFORMANCE
                | vk::DebugUtilsMessageTypeFlagsEXT::VALIDATION,
        )
        .pfn_user_callback(Some(vulkan_debug_utils_callback));

    let layer_names = [c"VK_LAYER_KHRONOS_validation"];
    let layer_name_ptrs = [layer_names[0].as_ptr() as *const c_char];
    let mut extension_names = Vec::new();
    // extension_names.push(debug_utils::NAME.as_ptr());
    extension_names.push(ash::khr::portability_enumeration::NAME.as_ptr());
    // Enabling this extension is a requirement when using `VK_KHR_portability_subset`
    extension_names.push(ash::khr::get_physical_device_properties2::NAME.as_ptr());

    let create_flags = vk::InstanceCreateFlags::ENUMERATE_PORTABILITY_KHR;
    let instance_create_info = vk::InstanceCreateInfo::default()
        .push_next(&mut debugcreateinfo)
        .application_info(&app_info)
        .flags(create_flags)
        .enabled_layer_names(layer_name_ptrs.as_slice())
        .enabled_extension_names(&extension_names);

    // Create a Vulkan entry point and an instance
    let entry;
    let instance;
    unsafe {
        entry = Entry::load().expect("Failed to create Entry");
        println!("entry: {:?}", entry.try_enumerate_instance_version());
        instance = match entry.create_instance(&instance_create_info, None) {
            Ok(instance) => instance,
            Err(err) => panic!("Failed to create instance: {}, {:?}", err, err),
        }
    }
    println!("instance: {:?}", instance.handle());
}

