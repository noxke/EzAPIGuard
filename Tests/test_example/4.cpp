#include <bits/stdc++.h>
#include<winsock2.h>
#pragma comment(lib,"ws2_32.lib")//���������̾�̬��
using namespace std;

//����URL
void ParseURL(string url, string&host, string&res)
{
	//����ֻ�Ǽ򵥽����������URL
	if (url.find("http://") != url.npos)
	{
		url = url.substr(7);//ɾ���ַ����е�http://
	}
	else if (url.find("https://") != url.npos)
	{
		url = url.substr(8);//ɾ���ַ����е�https://
	}
	//��ȡ���� ɾ��URLЭ��ͷ���studentwebsite.cn/index.html���ҵ���һ��"/"��λ�� �����±�
	int pos = url.find_first_of("/");
	host = url.substr(0, pos);
	//��ȡ��Դ��ַ
	res = url.substr(pos);
	//
	cout << "������" << host << endl;
	cout << "��Դ��" << res << endl;
}
int main(){
	//WSAStartup�洢�����������Ϣ
	WSADATA wsdata;
	//��ʼ���������ܹ�ʹ�õĺ����򷽷���
	WSAStartup(MAKEWORD(2, 2), &wsdata);
	//��ʼ������֮�󣬾��ܴ����׽��ֵ���

	//�����׽���
	SOCKET skt = socket(AF_INET, SOCK_STREAM, 0);
	if (skt == SOCKET_ERROR)
	{
		cout << "�����׽���ʧ��.." << endl;
		return 0;
	}
	else
	{
		cout << "�����׽��ֳɹ�.." << endl;
	}
	string host_url = "https://www.vcg.com/creative/";//URL
	string host;//����
	string res;//��Դ��ַ

    int t = 1;
    while(t < 100) {
        host_url += to_string(t++) + ".html";
        cout << host_url << '\n';
        //����URL������URL�ŷ�Ϊ����+�����������Դ��ַ����������Ĳ��֮���ǣ�������studentwebsite.cn����Դ��ַ��/index.html
        ParseURL(host_url, host, res);

        //����Ҫ���ӵķ�������ַ
        HOSTENT*ip = gethostbyname(host.c_str());//��ȡ������Ϣ���������IP��ַ
        
        //��IP��ַ�󶨵��׽���
        sockaddr_in address;
        memset(&address, 0, sizeof(sockaddr_in));//���ṹ���������б�����ʼ��Ϊ0
        address.sin_family = AF_INET;//��ѭ��Э����
        address.sin_port = htons(80);//�����URL�˿���80,һ��http�˿ں���80��htons�����ǽ��˿ں������ֽ���ת��Ϊ�����ֽ���
        memcpy(&address.sin_addr, ip->h_addr, 4);//ת��Ϊ4���ֽڵ�����IP��ַ
        
        //���ӷ�����
        int cflag = connect(skt, (SOCKADDR*)&address, sizeof(SOCKADDR));
        if (cflag == SOCKET_ERROR)
        {
            cout << "���ӷ�����ʧ��.." << endl;
            return 0;
        }
        else
        {
            cout << "���ӷ������ɹ�.." << endl;
        }
        //׼�����͸����������ͻ�����Ҫ����Ϣ����
        string req = "";
        req += "GET " + res + " HTTP/1.1\r\n";
        req += "Host: " + host + "\r\n";
        req += "User-Agent:*\r\n";
        req += "Connection:Keep-Alive\r\n";
        req += "\r\n";

        //��������������Ϣ
        int clen = send(skt, req.c_str(), req.length(), 0);
        
        //���ܷ��������ص���Ϣ
        string info;//���ܵ���Ϣ
        char ch;//ÿ�ν��ܵ���Ϣ
        int rlength = 0;//�������ݵ��ܴ�С
        
        int rlen = recv(skt, &ch, 1, 0);//ÿ�ν��ܵ����ݴ�С
        rlength += rlen;
        if(rlen == SOCKET_ERROR) {
            printf("���մ���\n");
            continue;
        }
        
        while (rlen != 0 && rlen != SOCKET_ERROR)
        {
            info += ch;
            rlen = recv(skt, &ch, 1, 0);//ÿ�ν��ܵ����ݴ�С
            cout << ch;
            Sleep(100);
            rlength += rlen;
        }
        
        //����ת�� ��ֹ�ڿ���̨��ʾ����
        char*pszBuffer = new char[info.length() + 1];
        wchar_t* pszWideBuffer = new wchar_t[(info.length() + 1) * 2];
        memset(pszWideBuffer, 0, (info.length() + 1) * 2);
        memset(pszBuffer, 0, info.length() + 1);
        MultiByteToWideChar(CP_UTF8, 0, info.c_str(), info.length(), pszWideBuffer, (info.length() + 1) * 2);//��unicode���룬ת��Ϊ���ֽ�
        WideCharToMultiByte(CP_ACP, 0, pszWideBuffer, wcslen(pszWideBuffer), pszBuffer, info.length() + 1, NULL, NULL);//�����ֽ�,ת��Ϊ����̨����
        
        //cout << pszBuffer;
        info = pszBuffer;
        delete[] pszBuffer;
        delete[] pszWideBuffer;
        
        //��ʾ
        cout << "�ͻ��˸������������ˣ�" << req.length() << "���ֽ�" << endl;
        cout << "���������ظ��ͻ����ˣ�" << rlength << "���ֽ�" << endl;
        cout << info << endl;//�ڿ���̨��ӡ�ӷ�����������Ϣ
        
        Sleep(rand() % 1000 + 1000);
    }
	system("pause");
	return 0;
}
