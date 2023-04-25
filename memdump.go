package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var (
	modkernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi                     = windows.NewLazySystemDLL("psapi.dll")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modkernel32.NewProc("Process32FirstW")
	procProcess32Next            = modkernel32.NewProc("Process32NextW")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")
	procReadProcessMemory        = modkernel32.NewProc("ReadProcessMemory")
	procGetProcessMemoryInfo     = modpsapi.NewProc("GetProcessMemoryInfo")
	procVirtualQueryEx           = modkernel32.NewProc("VirtualQueryEx")
)

const (
	MEM_COMMIT = 0x1000
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func setMemory(ptr unsafe.Pointer, value byte, size uintptr) {
	bytes := make([]byte, size)
	for i := range bytes {
		bytes[i] = value
	}
	copy((*[1 << 30]byte)(ptr)[:size:size], bytes)
}
func main() {
	a := app.New()
	w := a.NewWindow("Memory Dumper")

	outputLabel := widget.NewLabel("")
	scrollContainer := container.NewScroll(outputLabel)

	progress := widget.NewProgressBar()
	progress.Resize(fyne.NewSize(400, 10))

	dumpButton := widget.NewButton("Dump Memory", func() {
		entry := widget.NewEntry()
		entry.SetPlaceHolder("Enter folder name")

		confirm := func(response bool) {
			if response {
				folderName := entry.Text
				if folderName != "" {
					err := os.MkdirAll(folderName, 0755)
					if err != nil {
						outputLabel.SetText(fmt.Sprintf("Error creating folder: %v", err))
						return
					}
				}

				progressChannel := make(chan float64)
				statusChannel := make(chan string)

				go func() {
					output, err := runMemoryDumper(folderName, progressChannel, statusChannel)
					if err != nil {
						outputLabel.SetText(fmt.Sprintf("Error: %v", err))
					} else {
						outputLabel.SetText(output)
					}
				}()

				go func() {
					for {
						select {
						case progressValue := <-progressChannel:
							progress.SetValue(progressValue)
						case status := <-statusChannel:
							// Append the status update to the outputLabel
							existingText := outputLabel.Text
							outputLabel.SetText(existingText + status)
						}
					}
				}()

			}
		}

		dialog.ShowCustomConfirm("Create Folder", "Create", "Cancel", entry, confirm, w)
	})

	content := container.New(layout.NewBorderLayout(dumpButton, progress, nil, nil),
		dumpButton,
		scrollContainer,
		progress,
	)

	w.SetContent(content)
	w.Resize(fyne.NewSize(800, 600))
	w.ShowAndRun()
}

func runMemoryDumper(folderName string, progressChannel chan float64, statusChannel chan string) (string, error) {
	defer close(progressChannel)
	defer close(statusChannel)
	var output strings.Builder

	logFile, err := os.OpenFile("memory_dumper.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("Error creating log file: %v", err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	snapshot, err := createToolhelp32Snapshot()
	if err != nil {
		return "", fmt.Errorf("Error creating snapshot: %v", err)
	}
	defer syscall.CloseHandle(snapshot)

	processes, err := getProcessList(snapshot)
	if err != nil {
		return "", fmt.Errorf("Error getting process list: %v", err)
	}

	currentProcessID := syscall.Getpid()

	for index, process := range processes {
		if process.th32ProcessID == 0 {
			continue
		}

		if process.th32ProcessID == uint32(currentProcessID) {
			continue
		}

		processInfo := fmt.Sprintf("Process: %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)
		output.WriteString(processInfo)

		if err := dumpProcessMemory(process.th32ProcessID, process.szExeFile, folderName); err != nil {
			errMsg := fmt.Sprintf("Failed to dump memory: %v\n", err)
			output.WriteString(errMsg)
		} else {
			status := fmt.Sprintf("Successfully dumped memory for process %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)
			statusChannel <- status
		}

		progress := float64(index+1) / float64(len(processes))
		progressChannel <- progress
	}

	return output.String(), nil
}

// ProcessEntry32 is a PROCESSENTRY32 structure.
type ProcessEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [syscall.MAX_PATH]uint16
}

func createToolhelp32Snapshot() (syscall.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}

func getProcessList(snapshot syscall.Handle) ([]ProcessEntry32, error) {
	var processes []ProcessEntry32

	var process ProcessEntry32
	process.dwSize = uint32(unsafe.Sizeof(process))

	ret, _, err := procProcess32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&process)))
	if ret == 0 {
		return nil, err
	}

	for {
		processes = append(processes, process)

		process = ProcessEntry32{}
		process.dwSize = uint32(unsafe.Sizeof(process))

		ret, _, err := procProcess32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&process)))
		if ret == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}

	return processes, nil
}

type PROCESS_MEMORY_COUNTERS_EX struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

func protectionFlagsToString(protect uint32) string {
	flags := make([]string, 0)

	read := protect&windows.PAGE_READONLY != 0 || protect&windows.PAGE_READWRITE != 0 || protect&windows.PAGE_WRITECOPY != 0 || protect&windows.PAGE_EXECUTE_READ != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0
	write := protect&windows.PAGE_READWRITE != 0 || protect&windows.PAGE_WRITECOPY != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0
	execute := protect&windows.PAGE_EXECUTE != 0 || protect&windows.PAGE_EXECUTE_READ != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0

	if read {
		flags = append(flags, "R")
	}
	if write {
		flags = append(flags, "W")
	}
	if execute {
		flags = append(flags, "X")
	}

	return strings.Join(flags, "")
}

func dumpProcessMemory(processID uint32, exeFile [syscall.MAX_PATH]uint16, folderName string) error {
	exePath := syscall.UTF16ToString(exeFile[:])

	hProcess, _, err := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(0), uintptr(processID))
	if hProcess == 0 {
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	outputPath := filepath.Join(folderName, fmt.Sprintf("%s_%d.dmp", exePath, processID))
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	type MemoryRange struct {
		BaseAddress uintptr
		RegionSize  uintptr
		Protect     uint32
	}

	var memoryRanges []MemoryRange

	for baseAddress := uintptr(0); ; {
		baseAddress = (baseAddress + 0xFFFF) & ^uintptr(0xFFFF)
		var memoryBasicInfo MEMORY_BASIC_INFORMATION
		setMemory(unsafe.Pointer(&memoryBasicInfo), 0, unsafe.Sizeof(memoryBasicInfo))

		ret, _, _ := procVirtualQueryEx.Call(hProcess, baseAddress, uintptr(unsafe.Pointer(&memoryBasicInfo)), unsafe.Sizeof(memoryBasicInfo))

		if ret == 0 {
			break
		}

		if memoryBasicInfo.State == MEM_COMMIT {
			buffer := make([]byte, memoryBasicInfo.RegionSize)
			var bytesRead uintptr
			ret, _, err = procReadProcessMemory.Call(hProcess, memoryBasicInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), uintptr(memoryBasicInfo.RegionSize), uintptr(unsafe.Pointer(&bytesRead)))
			if ret != 0 {
				outputFile.Write(buffer[:bytesRead])
				memoryRanges = append(memoryRanges, MemoryRange{BaseAddress: baseAddress, RegionSize: memoryBasicInfo.RegionSize, Protect: memoryBasicInfo.Protect})
			}
		}

		baseAddress += memoryBasicInfo.RegionSize
	}

	log.Printf("Memory dump for PID %d saved to: %s\n", processID, outputPath)
	log.Printf("Memory ranges for PID %d:\n", processID)
	for _, memRange := range memoryRanges {
		protectionStr := protectionFlagsToString(memRange.Protect)
		log.Printf("Base address: %X, Region size: %X, Protection: %s\n", memRange.BaseAddress, memRange.RegionSize, protectionStr)
	}

	return nil
}
