cmake_minimum_required(VERSION 3.22)
if(CMAKE_HOST_APPLE AND NOT CMAKE_OSX_DEPLOYMENT_TARGET)
  set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS deployment target" FORCE)
endif()
project(opencore_next VERSION 0.1.0 LANGUAGES C)

set_property(GLOBAL PROPERTY I1N1_REPO_ENGINE_LOADED TRUE)
set(I1N1_ENGINE_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE INTERNAL "")

option(OCNEXT_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

function(ocnext_diagnostics target)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(OCNEXT_ENABLE_SANITIZERS)
      target_compile_options(${target} PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endif()
  endif()
endfunction()

add_library(ocnext_bridge SHARED src/bridge.c)
if(UNIX)
  target_sources(ocnext_bridge PRIVATE host/client/client.c)
endif()
target_include_directories(ocnext_bridge PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(ocnext_bridge PUBLIC c_std_11)
set_target_properties(ocnext_bridge PROPERTIES
  PREFIX ""
  OUTPUT_NAME "oclp-sandbox-amd64"
  VERSION ${PROJECT_VERSION}
  SOVERSION 0
  C_VISIBILITY_PRESET hidden)
target_compile_definitions(ocnext_bridge PRIVATE OCNEXT_BRIDGE_BUILD=1)
ocnext_diagnostics(ocnext_bridge)

add_library(ocnext_a64_sysreg STATIC runtime/isa/a64_sysreg.c)
target_include_directories(ocnext_a64_sysreg PUBLIC include)
target_compile_features(ocnext_a64_sysreg PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_sysreg)

add_library(ocnext_a64 STATIC runtime/isa/a64.c)
target_include_directories(ocnext_a64 PUBLIC include)
target_compile_features(ocnext_a64 PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64)

add_library(ocnext_ordering STATIC runtime/memory/ordering.c)
target_include_directories(ocnext_ordering PUBLIC include)
target_compile_features(ocnext_ordering PUBLIC c_std_11)
ocnext_diagnostics(ocnext_ordering)

add_library(ocnext_sha256 STATIC runtime/boot/sha256.c)
target_include_directories(ocnext_sha256 PUBLIC include)
target_compile_features(ocnext_sha256 PUBLIC c_std_11)
ocnext_diagnostics(ocnext_sha256)

add_library(ocnext_native_format STATIC runtime/substrate/native_format.c)
target_include_directories(ocnext_native_format PUBLIC include)
target_include_directories(ocnext_native_format PRIVATE
  include/ocnext third_party/nanoprintf)
target_compile_features(ocnext_native_format PUBLIC c_std_11)
ocnext_diagnostics(ocnext_native_format)

add_library(ocnext_elf_module STATIC runtime/substrate/backend_host/elf_module.c)
target_include_directories(ocnext_elf_module PUBLIC include)
target_compile_features(ocnext_elf_module PUBLIC c_std_11)
target_link_libraries(ocnext_elf_module PUBLIC ocnext_sha256)
ocnext_diagnostics(ocnext_elf_module)

add_library(ocnext_backend_tcg STATIC runtime/substrate/backend_host/tcg.c)
target_include_directories(ocnext_backend_tcg PUBLIC include)
target_compile_features(ocnext_backend_tcg PUBLIC c_std_11)
target_link_libraries(ocnext_backend_tcg PUBLIC ocnext_sha256)
ocnext_diagnostics(ocnext_backend_tcg)

add_library(ocnext_chained_fixups STATIC runtime/boot/chained_fixups.c)
target_include_directories(ocnext_chained_fixups PUBLIC include)
target_compile_features(ocnext_chained_fixups PUBLIC c_std_11)
target_link_libraries(ocnext_chained_fixups PUBLIC ocnext_sha256)
ocnext_diagnostics(ocnext_chained_fixups)

add_library(ocnext_a64_fp_control STATIC runtime/isa/a64_fp_control.c)
target_include_directories(ocnext_a64_fp_control PUBLIC include)
target_compile_features(ocnext_a64_fp_control PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_fp_control)

add_library(ocnext_a64_adc_carry STATIC runtime/isa/a64_adc_carry.c)
target_include_directories(ocnext_a64_adc_carry PUBLIC include)
target_compile_features(ocnext_a64_adc_carry PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_adc_carry)

add_library(ocnext_a64_divbit STATIC runtime/isa/a64_divbit.c)
target_include_directories(ocnext_a64_divbit PUBLIC include)
target_compile_features(ocnext_a64_divbit PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_divbit)

add_library(ocnext_a64_multiply STATIC runtime/isa/a64_multiply.c)
target_include_directories(ocnext_a64_multiply PUBLIC include)
target_compile_features(ocnext_a64_multiply PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_multiply)

add_library(ocnext_a64_ldra STATIC runtime/isa/a64_ldra.c)
target_include_directories(ocnext_a64_ldra PUBLIC include)
target_compile_features(ocnext_a64_ldra PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_ldra)

add_library(ocnext_a64_atomic STATIC runtime/isa/a64_atomic.c)
target_include_directories(ocnext_a64_atomic PUBLIC include)
target_compile_features(ocnext_a64_atomic PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_atomic)

add_library(ocnext_a64_simd_integer STATIC runtime/isa/a64_simd_integer.c)
target_include_directories(ocnext_a64_simd_integer PUBLIC include)
target_compile_features(ocnext_a64_simd_integer PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_simd_integer)

add_library(ocnext_a64_simd_ext STATIC runtime/isa/a64_simd_ext.c runtime/isa/a64_fp_soft.c)
target_include_directories(ocnext_a64_simd_ext PUBLIC include)
target_compile_features(ocnext_a64_simd_ext PUBLIC c_std_11)
target_link_libraries(ocnext_a64_simd_ext PUBLIC ocnext_a64_simd_integer)
ocnext_diagnostics(ocnext_a64_simd_ext)

add_library(ocnext_a64_fmov STATIC runtime/isa/a64_fmov.c)
target_include_directories(ocnext_a64_fmov PUBLIC include)
target_compile_features(ocnext_a64_fmov PUBLIC c_std_11)
target_link_libraries(ocnext_a64_fmov PUBLIC ocnext_a64_fp_control ocnext_a64_simd_integer)
ocnext_diagnostics(ocnext_a64_fmov)

add_library(ocnext_pci_capture STATIC runtime/device/pci_capture.c)
target_include_directories(ocnext_pci_capture PUBLIC include)
target_compile_features(ocnext_pci_capture PUBLIC c_std_11)
target_link_libraries(ocnext_pci_capture PUBLIC ocnext_sha256)
ocnext_diagnostics(ocnext_pci_capture)

add_library(ocnext_native_mmio STATIC runtime/device/native_mmio.c)
target_include_directories(ocnext_native_mmio PUBLIC include)
target_compile_features(ocnext_native_mmio PUBLIC c_std_11)
target_link_libraries(ocnext_native_mmio PUBLIC ocnext_pci_capture)
ocnext_diagnostics(ocnext_native_mmio)

add_library(ocnext_fixup_transaction STATIC runtime/boot/fixup_transaction.c)
target_include_directories(ocnext_fixup_transaction PUBLIC include)
target_compile_features(ocnext_fixup_transaction PUBLIC c_std_11)
target_link_libraries(ocnext_fixup_transaction PUBLIC ocnext_sha256 ocnext_pac_pointer)
ocnext_diagnostics(ocnext_fixup_transaction)

add_library(ocnext_fixup_index STATIC runtime/boot/fixup_index.c)
target_include_directories(ocnext_fixup_index PUBLIC include)
target_compile_features(ocnext_fixup_index PUBLIC c_std_11)
target_link_libraries(ocnext_fixup_index PUBLIC ocnext_chained_fixups ocnext_fixup_transaction)
ocnext_diagnostics(ocnext_fixup_index)

add_library(ocnext_pac_qarma5 STATIC runtime/crypto/pac_qarma5.c)
target_include_directories(ocnext_pac_qarma5 PUBLIC include)
target_compile_features(ocnext_pac_qarma5 PUBLIC c_std_11)
ocnext_diagnostics(ocnext_pac_qarma5)

add_library(ocnext_a64_pac_install STATIC runtime/isa/a64_pac_install.c)
target_include_directories(ocnext_a64_pac_install PUBLIC include)
target_compile_features(ocnext_a64_pac_install PUBLIC c_std_11)
ocnext_diagnostics(ocnext_a64_pac_install)
target_link_libraries(ocnext_a64 PUBLIC ocnext_a64_pac_install)

add_library(ocnext_pac_keys STATIC runtime/crypto/pac_keys.c)
target_include_directories(ocnext_pac_keys PUBLIC include)
target_compile_features(ocnext_pac_keys PUBLIC c_std_11)
ocnext_diagnostics(ocnext_pac_keys)

add_library(ocnext_pac_pointer STATIC runtime/crypto/pac_pointer.c)
target_include_directories(ocnext_pac_pointer PUBLIC include)
target_compile_features(ocnext_pac_pointer PUBLIC c_std_11)
target_link_libraries(ocnext_pac_pointer PUBLIC ocnext_pac_keys ocnext_pac_qarma5)
ocnext_diagnostics(ocnext_pac_pointer)
target_link_libraries(ocnext_a64 PUBLIC ocnext_pac_pointer ocnext_a64_fp_control ocnext_a64_simd_integer ocnext_a64_simd_ext ocnext_a64_fmov ocnext_a64_adc_carry ocnext_a64_divbit ocnext_a64_multiply ocnext_a64_ldra ocnext_a64_sysreg)
target_link_libraries(ocnext_a64 PUBLIC ocnext_a64_atomic)

add_library(ocnext_pac_service STATIC runtime/platform/pac_service.c)
target_include_directories(ocnext_pac_service PUBLIC include)
target_compile_features(ocnext_pac_service PUBLIC c_std_11)
target_link_libraries(ocnext_pac_service PUBLIC ocnext_pac_keys ocnext_pac_qarma5)
ocnext_diagnostics(ocnext_pac_service)

add_library(ocnext_vmapple_pac_model STATIC runtime/platform/vmapple_pac_model.c)
target_include_directories(ocnext_vmapple_pac_model PUBLIC include)
target_compile_features(ocnext_vmapple_pac_model PUBLIC c_std_11)
ocnext_diagnostics(ocnext_vmapple_pac_model)

add_library(ocnext_gicv3_model STATIC runtime/device/gicv3_model.c)
target_include_directories(ocnext_gicv3_model PUBLIC include)
target_compile_features(ocnext_gicv3_model PUBLIC c_std_11)
ocnext_diagnostics(ocnext_gicv3_model)

add_library(ocnext_generic_timer STATIC runtime/platform/generic_timer.c)
target_include_directories(ocnext_generic_timer PUBLIC include)
target_compile_features(ocnext_generic_timer PUBLIC c_std_11)
ocnext_diagnostics(ocnext_generic_timer)

add_library(ocnext_vmapple_cfg STATIC runtime/platform/vmapple_cfg.c)
target_include_directories(ocnext_vmapple_cfg PUBLIC include)
target_compile_features(ocnext_vmapple_cfg PUBLIC c_std_11)
target_link_libraries(ocnext_vmapple_cfg PUBLIC ocnext_sha256)
ocnext_diagnostics(ocnext_vmapple_cfg)

add_library(ocnext_backend_heap STATIC
  runtime/substrate/backend_host/heap.c
  runtime/substrate/backend_host/tlsf_port.c
  third_party/tlsf/tlsf.c)
target_include_directories(ocnext_backend_heap PUBLIC include)
# Freestanding headers apply only to this imported allocator/port target.
target_include_directories(ocnext_backend_heap PRIVATE
  runtime/substrate/backend_host/tlsf_include)
target_compile_features(ocnext_backend_heap PUBLIC c_std_11)
ocnext_diagnostics(ocnext_backend_heap)

add_library(ocnext_native_domain STATIC runtime/device/domain_policy.c)
target_include_directories(ocnext_native_domain PUBLIC include)
target_compile_features(ocnext_native_domain PUBLIC c_std_11)
ocnext_diagnostics(ocnext_native_domain)

add_library(ocnext_pci_inventory STATIC runtime/device/pci_inventory.c)
target_include_directories(ocnext_pci_inventory PUBLIC include)
target_compile_features(ocnext_pci_inventory PUBLIC c_std_11)
target_link_libraries(ocnext_pci_inventory PUBLIC ocnext_sha256)
ocnext_diagnostics(ocnext_pci_inventory)

add_library(ocnext_proxy STATIC runtime/control/proxy.c)
target_include_directories(ocnext_proxy PUBLIC include)
target_compile_features(ocnext_proxy PUBLIC c_std_11)
ocnext_diagnostics(ocnext_proxy)

add_library(ocnext_ram STATIC runtime/memory/ram.c)
target_include_directories(ocnext_ram PUBLIC include)
target_compile_features(ocnext_ram PUBLIC c_std_11)
ocnext_diagnostics(ocnext_ram)

add_library(ocnext_proxy_monitor STATIC runtime/control/monitor.c)
target_include_directories(ocnext_proxy_monitor PUBLIC include)
target_compile_features(ocnext_proxy_monitor PUBLIC c_std_11)
target_link_libraries(ocnext_proxy_monitor PUBLIC ocnext_proxy)
ocnext_diagnostics(ocnext_proxy_monitor)

add_executable(ocnext-entry-probe runtime/coordinator/entry_probe.c)
target_link_libraries(ocnext-entry-probe PRIVATE ocnext_a64 ocnext_ordering)
ocnext_diagnostics(ocnext-entry-probe)

add_library(ocnext_x86_features STATIC runtime/host/x86_features.c)
target_include_directories(ocnext_x86_features PUBLIC include)
target_compile_features(ocnext_x86_features PUBLIC c_std_11)
ocnext_diagnostics(ocnext_x86_features)

add_library(ocnext_mmu STATIC runtime/mmu/mmu.c)
target_include_directories(ocnext_mmu PUBLIC include)
target_compile_features(ocnext_mmu PUBLIC c_std_11)
ocnext_diagnostics(ocnext_mmu)

add_library(ocnext_mmu_cpu STATIC runtime/mmu/cpu_adapter.c)
target_include_directories(ocnext_mmu_cpu PUBLIC include)
target_compile_features(ocnext_mmu_cpu PUBLIC c_std_11)
target_link_libraries(ocnext_mmu_cpu PUBLIC ocnext_a64 ocnext_mmu ocnext_ordering)
ocnext_diagnostics(ocnext_mmu_cpu)

add_library(ocnext_boot_args STATIC runtime/boot/boot_args.c)
target_include_directories(ocnext_boot_args PUBLIC include)
target_compile_features(ocnext_boot_args PUBLIC c_std_11)
ocnext_diagnostics(ocnext_boot_args)

add_executable(ocnext-boot-args-study runtime/coordinator/boot_args_study.c)
target_link_libraries(ocnext-boot-args-study PRIVATE ocnext_boot_args)
ocnext_diagnostics(ocnext-boot-args-study)

target_link_libraries(ocnext-entry-probe PRIVATE ocnext_boot_args ocnext_sha256 ocnext_mmu_cpu)

add_library(ocnext_broker STATIC host/broker/broker.c)
target_include_directories(ocnext_broker PUBLIC include)
target_compile_features(ocnext_broker PUBLIC c_std_11)
target_link_libraries(ocnext_broker PUBLIC ocnext_bridge)
ocnext_diagnostics(ocnext_broker)

if(UNIX)
  add_executable(ocnext-broker host/broker/daemon.c)
  target_link_libraries(ocnext-broker PRIVATE ocnext_broker)
  ocnext_diagnostics(ocnext-broker)
endif()

install(TARGETS ocnext_bridge LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin)
install(FILES include/ocnext/bridge.h include/ocnext/client.h DESTINATION include/ocnext)
