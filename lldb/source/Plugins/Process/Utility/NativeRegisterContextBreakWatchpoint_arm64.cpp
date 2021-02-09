//===-- NativeRegisterContextBreakWatchpoint_arm64.cpp --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "NativeRegisterContextBreakWatchpoint_arm64.h"

#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"

using namespace lldb_private;

uint32_t
NativeRegisterContextBreakWatchpoint_arm64::NumSupportedHardwareBreakpoints() {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_BREAKPOINTS));
  llvm::Error error = ReadHardwareDebugInfo();
  if (error) {
    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log, "failed to read debug registers: {0}", err_msg);
    return 0;
  }

  return m_max_hbp_supported;
}

uint32_t NativeRegisterContextBreakWatchpoint_arm64::SetHardwareBreakpoint(
    lldb::addr_t addr, size_t size) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_BREAKPOINTS));
  LLDB_LOG(log, "addr: {0:x}, size: {1:x}", addr, size);

  // Read hardware breakpoint and watchpoint information.
  llvm::Error error = ReadHardwareDebugInfo();
  if (error) {
    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to set breakpoint: failed to read debug registers: {0}",
             err_msg);
    return LLDB_INVALID_INDEX32;
  }

  uint32_t control_value = 0, bp_index = 0;

  // Check if size has a valid hardware breakpoint length.
  if (size != 4)
    return LLDB_INVALID_INDEX32; // Invalid size for a AArch64 hardware
                                 // breakpoint

  // Check 4-byte alignment for hardware breakpoint target address.
  if (addr & 0x03)
    return LLDB_INVALID_INDEX32; // Invalid address, should be 4-byte aligned.

  // Setup control value
  control_value = 0;
  control_value |= ((1 << size) - 1) << 5;
  control_value |= (2 << 1) | 1;

  // Iterate over stored breakpoints and find a free bp_index
  bp_index = LLDB_INVALID_INDEX32;
  for (uint32_t i = 0; i < m_max_hbp_supported; i++) {
    if ((m_hbr_regs[i].control & 1) == 0) {
      bp_index = i; // Mark last free slot
    } else if (m_hbr_regs[i].address == addr) {
      return LLDB_INVALID_INDEX32; // We do not support duplicate breakpoints.
    }
  }

  if (bp_index == LLDB_INVALID_INDEX32)
    return LLDB_INVALID_INDEX32;

  // Update breakpoint in local cache
  m_hbr_regs[bp_index].real_addr = addr;
  m_hbr_regs[bp_index].address = addr;
  m_hbr_regs[bp_index].control = control_value;

  // PTRACE call to set corresponding hardware breakpoint register.
  error = WriteHardwareDebugRegs(eDREGTypeBREAK);

  if (error) {
    m_hbr_regs[bp_index].address = 0;
    m_hbr_regs[bp_index].control &= ~1;

    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to set breakpoint: failed to write debug registers: {0}",
             err_msg);
    return LLDB_INVALID_INDEX32;
  }

  return bp_index;
}

bool NativeRegisterContextBreakWatchpoint_arm64::ClearHardwareBreakpoint(
    uint32_t hw_idx) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_BREAKPOINTS));
  LLDB_LOG(log, "hw_idx: {0}", hw_idx);

  // Read hardware breakpoint and watchpoint information.
  llvm::Error error = ReadHardwareDebugInfo();
  if (error) {
    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to clear breakpoint: failed to read debug registers: {0}",
             err_msg);
    return false;
  }

  if (hw_idx >= m_max_hbp_supported)
    return false;

  // Create a backup we can revert to in case of failure.
  lldb::addr_t tempAddr = m_hbr_regs[hw_idx].address;
  uint32_t tempControl = m_hbr_regs[hw_idx].control;

  m_hbr_regs[hw_idx].control &= ~1;
  m_hbr_regs[hw_idx].address = 0;

  // PTRACE call to clear corresponding hardware breakpoint register.
  error = WriteHardwareDebugRegs(eDREGTypeBREAK);

  if (error) {
    m_hbr_regs[hw_idx].control = tempControl;
    m_hbr_regs[hw_idx].address = tempAddr;

    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to clear breakpoint: failed to write debug registers: {0}",
             err_msg);
    return false;
  }

  return true;
}

Status NativeRegisterContextBreakWatchpoint_arm64::GetHardwareBreakHitIndex(
    uint32_t &bp_index, lldb::addr_t trap_addr) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_BREAKPOINTS));

  LLDB_LOGF(log, "NativeRegisterContextBreakWatchpoint_arm64::%s()",
            __FUNCTION__);

  lldb::addr_t break_addr;

  for (bp_index = 0; bp_index < m_max_hbp_supported; ++bp_index) {
    break_addr = m_hbr_regs[bp_index].address;

    if ((m_hbr_regs[bp_index].control & 0x1) && (trap_addr == break_addr)) {
      m_hbr_regs[bp_index].hit_addr = trap_addr;
      return Status();
    }
  }

  bp_index = LLDB_INVALID_INDEX32;
  return Status();
}

Status
NativeRegisterContextBreakWatchpoint_arm64::ClearAllHardwareBreakpoints() {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_BREAKPOINTS));

  LLDB_LOGF(log, "NativeRegisterContextBreakWatchpoint_arm64::%s()",
            __FUNCTION__);

  // Read hardware breakpoint and watchpoint information.
  llvm::Error error = ReadHardwareDebugInfo();
  if (error)
    return Status(std::move(error));

  lldb::addr_t tempAddr = 0;
  uint32_t tempControl = 0;

  for (uint32_t i = 0; i < m_max_hbp_supported; i++) {
    if (m_hbr_regs[i].control & 0x01) {
      // Create a backup we can revert to in case of failure.
      tempAddr = m_hbr_regs[i].address;
      tempControl = m_hbr_regs[i].control;

      // Clear watchpoints in local cache
      m_hbr_regs[i].control &= ~1;
      m_hbr_regs[i].address = 0;

      // Ptrace call to update hardware debug registers
      error = WriteHardwareDebugRegs(eDREGTypeBREAK);

      if (error) {
        m_hbr_regs[i].control = tempControl;
        m_hbr_regs[i].address = tempAddr;

        return Status(std::move(error));
      }
    }
  }

  return Status();
}

uint32_t
NativeRegisterContextBreakWatchpoint_arm64::NumSupportedHardwareWatchpoints() {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  llvm::Error error = ReadHardwareDebugInfo();
  if (error) {
    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log, "failed to read debug registers: {0}", err_msg);
    return 0;
  }

  return m_max_hwp_supported;
}

uint32_t NativeRegisterContextBreakWatchpoint_arm64::SetHardwareWatchpoint(
    lldb::addr_t addr, size_t size, uint32_t watch_flags) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "addr: {0:x}, size: {1:x} watch_flags: {2:x}", addr, size,
           watch_flags);

  // Read hardware breakpoint and watchpoint information.
  llvm::Error error = ReadHardwareDebugInfo();
  if (error) {
    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to set watchpoint: failed to read debug registers: {0}",
             err_msg);
    return LLDB_INVALID_INDEX32;
  }

  uint32_t control_value = 0, wp_index = 0;
  lldb::addr_t real_addr = addr;

  // Check if we are setting watchpoint other than read/write/access Also
  // update watchpoint flag to match AArch64 write-read bit configuration.
  switch (watch_flags) {
  case 1:
    watch_flags = 2;
    break;
  case 2:
    watch_flags = 1;
    break;
  case 3:
    break;
  default:
    return LLDB_INVALID_INDEX32;
  }

  // Check if size has a valid hardware watchpoint length.
  if (size != 1 && size != 2 && size != 4 && size != 8)
    return LLDB_INVALID_INDEX32;

  // Check 8-byte alignment for hardware watchpoint target address. Below is a
  // hack to recalculate address and size in order to make sure we can watch
  // non 8-byte aligned addresses as well.
  if (addr & 0x07) {
    uint8_t watch_mask = (addr & 0x07) + size;

    if (watch_mask > 0x08)
      return LLDB_INVALID_INDEX32;
    else if (watch_mask <= 0x02)
      size = 2;
    else if (watch_mask <= 0x04)
      size = 4;
    else
      size = 8;

    addr = addr & (~0x07);
  }

  // Setup control value
  control_value = watch_flags << 3;
  control_value |= ((1 << size) - 1) << 5;
  control_value |= (2 << 1) | 1;

  // Iterate over stored watchpoints and find a free wp_index
  wp_index = LLDB_INVALID_INDEX32;
  for (uint32_t i = 0; i < m_max_hwp_supported; i++) {
    if ((m_hwp_regs[i].control & 1) == 0) {
      wp_index = i; // Mark last free slot
    } else if (m_hwp_regs[i].address == addr) {
      return LLDB_INVALID_INDEX32; // We do not support duplicate watchpoints.
    }
  }

  if (wp_index == LLDB_INVALID_INDEX32)
    return LLDB_INVALID_INDEX32;

  // Update watchpoint in local cache
  m_hwp_regs[wp_index].real_addr = real_addr;
  m_hwp_regs[wp_index].address = addr;
  m_hwp_regs[wp_index].control = control_value;

  // PTRACE call to set corresponding watchpoint register.
  error = WriteHardwareDebugRegs(eDREGTypeWATCH);

  if (error) {
    m_hwp_regs[wp_index].address = 0;
    m_hwp_regs[wp_index].control &= ~1;

    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to set watchpoint: failed to write debug registers: {0}",
             err_msg);
    return LLDB_INVALID_INDEX32;
  }

  return wp_index;
}

bool NativeRegisterContextBreakWatchpoint_arm64::ClearHardwareWatchpoint(
    uint32_t wp_index) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "wp_index: {0}", wp_index);

  // Read hardware breakpoint and watchpoint information.
  llvm::Error error = ReadHardwareDebugInfo();
  if (error) {
    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to clear watchpoint: failed to read debug registers: {0}",
             err_msg);
    return false;
  }

  if (wp_index >= m_max_hwp_supported)
    return false;

  // Create a backup we can revert to in case of failure.
  lldb::addr_t tempAddr = m_hwp_regs[wp_index].address;
  uint32_t tempControl = m_hwp_regs[wp_index].control;

  // Update watchpoint in local cache
  m_hwp_regs[wp_index].control &= ~1;
  m_hwp_regs[wp_index].address = 0;

  // Ptrace call to update hardware debug registers
  error = WriteHardwareDebugRegs(eDREGTypeWATCH);

  if (error) {
    m_hwp_regs[wp_index].control = tempControl;
    m_hwp_regs[wp_index].address = tempAddr;

    auto err_msg = llvm::toString(std::move(error));
    LLDB_LOG(log,
             "unable to clear watchpoint: failed to write debug registers: {0}",
             err_msg);
    return false;
  }

  return true;
}

Status
NativeRegisterContextBreakWatchpoint_arm64::ClearAllHardwareWatchpoints() {
  // Read hardware breakpoint and watchpoint information.
  llvm::Error error = ReadHardwareDebugInfo();
  if (error)
    return Status(std::move(error));

  lldb::addr_t tempAddr = 0;
  uint32_t tempControl = 0;

  for (uint32_t i = 0; i < m_max_hwp_supported; i++) {
    if (m_hwp_regs[i].control & 0x01) {
      // Create a backup we can revert to in case of failure.
      tempAddr = m_hwp_regs[i].address;
      tempControl = m_hwp_regs[i].control;

      // Clear watchpoints in local cache
      m_hwp_regs[i].control &= ~1;
      m_hwp_regs[i].address = 0;

      // Ptrace call to update hardware debug registers
      error = WriteHardwareDebugRegs(eDREGTypeWATCH);

      if (error) {
        m_hwp_regs[i].control = tempControl;
        m_hwp_regs[i].address = tempAddr;

        return Status(std::move(error));
      }
    }
  }

  return Status();
}

uint32_t NativeRegisterContextBreakWatchpoint_arm64::GetWatchpointSize(
    uint32_t wp_index) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "wp_index: {0}", wp_index);

  switch ((m_hwp_regs[wp_index].control >> 5) & 0xff) {
  case 0x01:
    return 1;
  case 0x03:
    return 2;
  case 0x0f:
    return 4;
  case 0xff:
    return 8;
  default:
    return 0;
  }
}

bool NativeRegisterContextBreakWatchpoint_arm64::WatchpointIsEnabled(
    uint32_t wp_index) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "wp_index: {0}", wp_index);

  if ((m_hwp_regs[wp_index].control & 0x1) == 0x1)
    return true;
  else
    return false;
}

Status NativeRegisterContextBreakWatchpoint_arm64::GetWatchpointHitIndex(
    uint32_t &wp_index, lldb::addr_t trap_addr) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "wp_index: {0}, trap_addr: {1:x}", wp_index, trap_addr);

  uint32_t watch_size;
  lldb::addr_t watch_addr;

  for (wp_index = 0; wp_index < m_max_hwp_supported; ++wp_index) {
    watch_size = GetWatchpointSize(wp_index);
    watch_addr = m_hwp_regs[wp_index].address;

    if (WatchpointIsEnabled(wp_index) && trap_addr >= watch_addr &&
        trap_addr < watch_addr + watch_size) {
      m_hwp_regs[wp_index].hit_addr = trap_addr;
      return Status();
    }
  }

  wp_index = LLDB_INVALID_INDEX32;
  return Status();
}

lldb::addr_t NativeRegisterContextBreakWatchpoint_arm64::GetWatchpointAddress(
    uint32_t wp_index) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "wp_index: {0}", wp_index);

  if (wp_index >= m_max_hwp_supported)
    return LLDB_INVALID_ADDRESS;

  if (WatchpointIsEnabled(wp_index))
    return m_hwp_regs[wp_index].real_addr;
  else
    return LLDB_INVALID_ADDRESS;
}

lldb::addr_t
NativeRegisterContextBreakWatchpoint_arm64::GetWatchpointHitAddress(
    uint32_t wp_index) {
  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "wp_index: {0}", wp_index);

  if (wp_index >= m_max_hwp_supported)
    return LLDB_INVALID_ADDRESS;

  if (WatchpointIsEnabled(wp_index))
    return m_hwp_regs[wp_index].hit_addr;
  else
    return LLDB_INVALID_ADDRESS;
}
