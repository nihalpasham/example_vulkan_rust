use ash::{ext::debug_utils, vk, Entry};
use std::{
    ffi::{c_char, CStr},
    time,
};

use gpu_allocator::{vulkan::*, MemoryLocation};

unsafe extern "system" fn vulkan_debug_utils_callback(
    message_severity: vk::DebugUtilsMessageSeverityFlagsEXT,
    message_type: vk::DebugUtilsMessageTypeFlagsEXT,
    p_callback_data: *const vk::DebugUtilsMessengerCallbackDataEXT,
    _p_user_data: *mut std::ffi::c_void,
) -> vk::Bool32 {
    let message = CStr::from_ptr((*p_callback_data).p_message);
    let severity = format!("{:?}", message_severity).to_lowercase();
    let ty = format!("{:?}", message_type).to_lowercase();
    println!(
        "[DBG]: [{}][{}] {}",
        severity,
        ty,
        message.to_str().unwrap()
    );
    vk::FALSE
}

fn main() {
    let app_name = c"Vulkan Test App";
    let app_info = vk::ApplicationInfo::default()
        .application_name(app_name)
        .application_version(0)
        .engine_name(app_name)
        .engine_version(0)
        .api_version(vk::make_api_version(0, 1, 2, 296));

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
    extension_names.push(debug_utils::NAME.as_ptr());
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
        entry = Entry::load().expect("Failed to load Vulkan entry");
        let instance_version;
        match {
            entry
                .try_enumerate_instance_version()
                .expect("Failed to enumerate instance version")
        } {
            // Vulkan 1.1+
            Some(version) => {
                let major = vk::api_version_major(version);
                let minor = vk::api_version_minor(version);
                let patch = vk::api_version_patch(version);
                instance_version = format!("{}.{}.{}", major, minor, patch);
            }
            // Vulkan 1.0
            None => {
                instance_version = format!("1.0");
            }
        }
        println!("Vulkan version: {}", instance_version);
        instance = match entry.create_instance(&instance_create_info, None) {
            Ok(instance) => instance,
            Err(err) => panic!("Failed to create instance: {}, {:?}", err, err),
        }
    }

    // Get a handle to a physical device, logical device, and queue.
    let physical_device;
    let queue_family_index;
    let priorities;
    let device;
    let queue;
    unsafe {
        physical_device = instance.enumerate_physical_devices().unwrap()[0];
        let device_queue_family_properties =
            instance.get_physical_device_queue_family_properties(physical_device);

        println!(
            "Queue family count: {}",
            device_queue_family_properties.len(),
        );
        device_queue_family_properties
            .iter()
            .enumerate()
            .for_each(|(index, info)| {
                println!(
                    "Queue family index: {},
                     Queue count: {},
                     Queue flags: {:?}, 
                     Queue timestamp valid bits: {},
                     Image transfer Op Granularity: {:?}\n",
                    index,
                    info.queue_count,
                    info.queue_flags,
                    info.timestamp_valid_bits,
                    info.min_image_transfer_granularity
                );
            });
        queue_family_index = 0;
        priorities = [1.0];

        let queue_info = vk::DeviceQueueCreateInfo::default()
            .queue_family_index(queue_family_index)
            .queue_priorities(&priorities);

        let mut extension_names = Vec::new();
        extension_names.push(ash::khr::portability_subset::NAME.as_ptr());

        let device_create_info = vk::DeviceCreateInfo::default()
            .queue_create_infos(std::slice::from_ref(&queue_info))
            .enabled_extension_names(&extension_names);

        device = instance
            .create_device(physical_device, &device_create_info, None)
            .expect("Failed to create device");
        queue = device.get_device_queue(queue_family_index, 0);
    }

    // Create an allocator to allocate a buffer.
    let mut allocator = Allocator::new(&AllocatorCreateDesc {
        instance: instance.clone(),
        device: device.clone(),
        physical_device,
        debug_settings: Default::default(),
        buffer_device_address: false, // Ideally, check the BufferDeviceAddressFeatures struct.
        allocation_sizes: Default::default(),
    })
    .expect("Failed to create allocator");

    let buffer_create_info = vk::BufferCreateInfo::default()
        .size(1024)
        .usage(vk::BufferUsageFlags::TRANSFER_DST);
    let buffer = unsafe { device.create_buffer(&buffer_create_info, None) }.unwrap();
    let requirements = unsafe { device.get_buffer_memory_requirements(buffer) };
    let allocation = allocator
        .allocate(&AllocationCreateDesc {
            name: "Example allocation",
            requirements,
            location: MemoryLocation::GpuToCpu,
            linear: true, // Buffers are always linear
            allocation_scheme: AllocationScheme::GpuAllocatorManaged,
        })
        .expect("Failed to allocate buffer");

    // Bind allocation to the buffer handle
    unsafe {
        device
            .bind_buffer_memory(buffer, allocation.memory(), allocation.offset())
            .unwrap()
    };

    // Create the command pool, command buffers
    let pool_create_info = vk::CommandPoolCreateInfo::default()
        .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER)
        .queue_family_index(queue_family_index);

    let pool;
    let command_buffers;
    unsafe {
        pool = device.create_command_pool(&pool_create_info, None).unwrap();
        let command_buffer_allocate_info = vk::CommandBufferAllocateInfo::default()
            .command_buffer_count(1)
            .command_pool(pool)
            .level(vk::CommandBufferLevel::PRIMARY);

        command_buffers = device
            .allocate_command_buffers(&command_buffer_allocate_info)
            .expect("Failed to allocate command buffers");
    }

    // Record a copy command to copy data into a command buffer.
    let data = [0x40; 1024];
    let begin_info = vk::CommandBufferBeginInfo::default();
    unsafe {
        device
            .begin_command_buffer(command_buffers[0], &begin_info)
            .expect("Failed to begin command buffer");
        device.cmd_fill_buffer(
            command_buffers[0],
            buffer,
            allocation.offset(),
            allocation.size(),
            data.len() as u32,
        );
        device.end_command_buffer(command_buffers[0]).unwrap();
    }

    // Create a synchronization object (Fence)
    let fence = {
        let create_info = vk::FenceCreateInfo::default();
        unsafe {
            device
                .create_fence(&create_info, None)
                .expect("Failed to create a fence")
        }
    };

    // Submit command buffer containing a single transfer command to our queue.
    unsafe {
        device
            .queue_submit(
                queue,
                &[vk::SubmitInfo::default().command_buffers(&command_buffers)],
                fence,
            )
            .expect("failed to submit command buffer");
    }

    // Wait for the execution to complete
    let start = time::Instant::now();
    unsafe {
        device
            .wait_for_fences(std::slice::from_ref(&fence), true, u64::MAX)
            .expect("Failed to wait")
    };
    println!("GPU took {:?}", time::Instant::now() - start);

    let data = allocation
        .mapped_slice()
        .expect("Cannot access buffer from Host");

    println!("Time taken: {:?}", time::Instant::now() - start);
    println!("Data read from Gpu {:?}", data);

    // Clean up
    unsafe {
        device.destroy_fence(fence, None);
        // device.destroy_command_pool(pool, None);
        allocator.free(allocation).unwrap();
        drop(allocator);
        device.destroy_buffer(buffer, None);
        device.destroy_command_pool(pool, None);
        device.destroy_device(None);
        instance.destroy_instance(None);
    }
}
