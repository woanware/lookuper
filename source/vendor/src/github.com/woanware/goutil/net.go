package goutil

import (
	"os"
	"net/http"
	"errors"
	"fmt"
	"io"
	"net"
	"encoding/binary"
	"math/big"
)

// ##### Methods #############################################################

func Ipv4ToInt(IPv4Addr net.IP) uint32 {
	IPv6Int := big.NewInt(0)
	IPv6Int.SetBytes(IPv4Addr.To4())
	return uint32(IPv6Int.Int64())
}

// Makes an net.IP struct from an integer
func IntToIpBigEndian(ipAddr uint32) net.IP {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, ipAddr)
	return net.IP(ipByte)
}

// Makes an net.IP struct from an integer
func IntToIpLittleEndian(ipAddr uint32) net.IP {
	ipByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipByte, ipAddr)
	return net.IP(ipByte)
}

// Converts a string representation of an IP address to an integer
func InetAton(ipAddr string) (uint32, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return 0, errors.New("Wrong IP address format")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

/* RFC1918: IPV4 Private Networks (10.0.0.0/8, 192.168.0.0./16, 172.16.0.0/12)
Should be used by initialising the variables below and then passing into the method to improve performance

rfc1918ten = net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
rfc1918oneninetwo =  net.IPNet{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}
rfc1918oneseventwo =  net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}
*/
func IsIpAddressRfc1918(ten net.IPNet,
	oneNineTwo net.IPNet,
	oneSevenTwo net.IPNet,
	ip net.IP) bool {
	return ten.Contains(ip) ||
			oneNineTwo.Contains(ip) ||
			oneSevenTwo.Contains(ip)
}

//
func DownloadToFile(url string, file string) (error) {
	output, err := os.Create(file)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating download file: %v (%s)", err, file))
	}
	defer output.Close()

	response, err := http.Get(url)
	if err != nil {
		return errors.New(fmt.Sprintf("Error downloading from URL: %v (%s)", err, url))
	}
	defer response.Body.Close()

	_, err = io.Copy(output, response.Body)
	if err != nil {
		return errors.New(fmt.Sprintf("Error outputing downloaded file: %v (%s)", err, file))
	}

	return nil
}
