package Antivm

import (
		    "github.com/stackexchange/wmi"
	str 	"strings"
	ps 	  "github.com/mitche11h/go-ps"
)
type Win32_DiskDrive struct {
	PNPDeviceID string
	Size		uint64
}

const (
	B = 1
	KB = 1024 * B
	MB = 1024 * KB
	GB = 1024 * MB
)

MAClist := []string{"00:16:3E", "00:1D:D8", "00:03:FF", "00:18:51", "58:9C:FC", "50:6B:8D", "54:52:00", "96:00:00", "00:50:56", "00:0C:29", "05:05:69",
"00:1C:14", "00:1C:42", "02:42", "00:15:5D", "08:00:27", "52:54:00", "00:21:F6", "00:14:4F", "00:0F:4B"}

MemoryDumpList := []string{"DumpIt.exe", "RAMMAP.exe", "RAMMAP64", "vmap.exe", "volatility.exe"}

Emulated := []string {"virtual","vmware","vbox"}

ProcessListLook := []string{"processhacker.exe","procmon.exe","pestudio.exe","procmon64.exe", "x32dbg.exe", "x64dbg.exe",
"CFF Explorer.exe", "procexp64.exe", "sysmon.exe", "TaniumClient.exe", "Taniun.exe", "SplunkUniversalForwarder.exe",
"procexp.exe", "pslist.exe", "tcpview.exe", "tcpvcon.exe", "dbgview.exe", "RAMMap.exe", "RAMMap64.exe",
"ollydbg.exe", "agent.py", "autoruns.exe", "autorunsc.exe", "filemon.exe", "regmon.exe", "idaq.exe", "idaq64.exe",
"ImmunityDebugger.exe", "Wireshark.exe", "dumpcap.exe", "HookExplorer.exe", "ImportREC.exe", "PETools.exe",
"LordPE.exe", "SysInspector.exe", "proc_analyzer.exe", "sysAnalyzer.exe", "sniff_hit.exe", "windbg.exe",
"joeboxcontrol.exe", "joeboxserver.exe", "joeboxserver.exe", "ResourceHacker.exe", "Fiddler.exe", "httpdebugger.exe"}


func GetNetworkAdapter() (Win32_NetworkAdapter, error) {
	var net []NetworkAdapter
	var NetworkAdapter []win32.Win32_NetworkAdapter
	q := wmi.Query(&NetworkAdapter, "")

	if err := wmi.Query(q, &NetworkAdapter); err != nil {
		return net, err
	}
	for _, n := range NetworkAdapter {
		net := NetworkAdapter{
			AdapterType:  n.AdapterType,
			Name:         n.Name,
			Manufacturer: n.Manufacturer,
			ServiceName:  n.ServiceName,
		}
		NetworkAdapter = append(NetworkAdapter, net)
	}
	return net, nil
}

func SoundCardCheck() (Win32_SoundDevice, error) {
	var Sound []SoundDevice
	var SoundDevice []win32.Win32_SoundDevice
	q := wmi.Query(&SoundDevice, "")
		if err := wmi.Query(q, &SoundDevice); err != nil {
		return Sound, err
		}
		for _, s := range SoundDevice {
			Sound := SoundDevice{
				Location:		s.Location
				Name:			s.Name
				PrinterState:	s.PrinterState
				PrinterStatus:	s.PrinterStatus
				ShareName:		s.ShareName
				SystemName:		s.SystemName
			}
			Sound = append(SoundDevice, Sound)	
		}
		return Sound, nil
	}

func MouseCheck() (Win32_PointingDevice, error) {
	var Mouse []PointingDevice
	var MouseDevice []win32.Win32_PointingDevice
	q := wmi.Query(&PointingDevice, "")
	if err := wmi.Query(q, &PointingDevice); err != nil {
	return Mouse, err
	}
	for _, p := range PointingDevice {
		Mouse := PointingDevice{
			PNPDeviceID:	p.PNPDeviceID
			Name:			p.Name
			HardwareType:	p.HardwareType
			SystemName:		p.SystemName
			PSComputerName:	p.PSComputerName
		}
		Mouse = append(MouseDevice, Mouse)	
	}
	return Mouse, nil
	}

func GetMacAddr(Win32_NetworkAdapter, error) {
	var MAC []NetworkAdapter
	var MACAddress []win32.Win32_NetworkAdapter
	q := wmi.Query(&NetworkAdapter, "")
	if err := wmi.Query(q, &NetworkAdapter); err != nil {
		return MAC, err
	}
	for _, m := range NetworkAdapter {
		MAC := NetworkAdapter{
			ServiceName:	m.ServiceName
			MACAddress:		m.MACAddress
			Name:			m.Name
			AdapterType:	m.AdapterType
		}
		MAC = append(MACAddres, MAC)
	}
	return MAC, nil
}

func DiskSizeCheck(Win32_DiskDrive, error) {
	var disk []DiskDrive
	var diskdrive []win32.Win32_DiskDrive
	q := wmi.Query(&diskdrive, "")
	if err := wmi.Query(q, &diskdrive); err != nil {
		return disk, err
	}
	for _, d := range diskdrive {
		disk := DiskDrive{
			Partitions:	d.Partitions
			DeviceID:	d.DeviceID
			Model:		d.Model
			Size:		d.Size
		}
		disk = append(diskdrive,disk)
	}
	return disk, err
}

func DiskSizeTotal(Win32_DiskDrive, maxSize uint64) bool {
	var disk []Diskdrive
	var diskdrive []win32.Win32_DiskDrive
	for _, diskinformation := range diskdrive{
		return (diskinformation.Size / GB) < maxSize
	}
	return false
}

func BySizeDisk(maxSize uint64) bool {
	return diskTotalSize(maxSize)
}

func ISVirtualDisk(Win32_DiskDrive) bool {
	var disk []Diskdrive
	var diskdrive []win32.Win32_DiskDrive
	q:= wmi.Query(&diskdrive, "")
	for _, diskinformation := range diskdrive {
		return Emulated, diskinformation.PNPDeviceID
	}
	return false
}


func MemoryCheck() bool {
	MemoryCheck, _ := ps.Process()

	for processname := range ProcessListLook {
		process := ps.Process
		processlower := str.ToLower(process.Executable())
		
		if ProccessListLook(MemoryDumpList, processlower){
			return true
		}
	}
	return false
}
