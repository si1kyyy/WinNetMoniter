#include <iostream>
#include <Windows.h>
#include <windivert.h>

// https://reqrypt.org/windivert-doc.html#introduction




int main()
{
	HANDLE mHandle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK,0,0);

	PVOID buf = malloc(0x1000000);
	int time = 0;
	WINDIVERT_ADDRESS addr = { 0 };
	while (true)
	{
		if (WinDivertRecv(mHandle, buf, 0x1000000, NULL, &addr))
		{
			PWINDIVERT_IPHDR ipHead = (PWINDIVERT_IPHDR)buf;
			PWINDIVERT_TCPHDR tcpHead = (PWINDIVERT_TCPHDR)((PUCHAR)buf + sizeof(WINDIVERT_IPHDR));
			UINT16 fullLen = ipHead->Length;
			UINT16 dataLen = ipHead->Length - sizeof(WINDIVERT_IPHDR) - sizeof(WINDIVERT_TCPHDR);
			char srcIp[100] = { 0 };
			char dstIp[100] = { 0 };
			WinDivertHelperFormatIPv4Address(ipHead->SrcAddr, srcIp, 100);
			WinDivertHelperFormatIPv4Address(ipHead->DstAddr, dstIp, 100);

			printf("srcIP:[%-15s - %-5d]\tdstIP:[%-15s - %-5d]\tsize:0x%02X\tdata:", srcIp, tcpHead->SrcPort, dstIp, tcpHead->DstPort, dataLen);
			DWORD printSize = dataLen >= 50 ? 50 : dataLen;
			for (size_t i = 0; i < printSize; i++)
			{
				printf("%02X ", ((PUCHAR)buf)[i+sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR)]);
			}
			printf("\r\n");

			WinDivertHelperCalcChecksums(buf, fullLen, &addr, 0);
			WinDivertSend(mHandle, buf, fullLen, 0, &addr);
		}
		//time++;
	}
	printf("done!\r\n");
	WinDivertClose(mHandle);

	getchar();
	return 1;
}

