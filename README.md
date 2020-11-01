# snipy
This is a sniffing module written in Python and it was used for the research of VoIP security.<br>
The papers describing this research are available here: 
 * [A study on the risk of taking out specific information by VoIP sniffing technique](https://www.koreascience.or.kr/article/JAKO201810063224583.page)

   이동건 (광운대학교 소프트웨어학과); 최웅철 (광운대학교 소프트웨어학과)<br>
   Received : 2018.11.26 / Accepted : 2018.12.14 / Published : 2018.12.30
   > **Abstract** <br>
   > *Recently, VoIP technology is widely used in our daily life. Even VoIP has become a
technology that can be easily accessed from services such as home phone as well as
KakaoTalk.[1] Most of these Internet telephones use the RTP protocol. However, there is a
vulnerability that the audio data of users can be intercepted through packet sniffing in the
RTP protocol. So we want to create a tool to check the security level of a VoIP network
using the RTP protocol. To do so, we capture data packet from and to these VoIP networks.
For this purpose, we first configure a virtual VoIP network using Raspberry Pi and show the
security vulnerability by applying our developed sniffing tool to the VoIP network. We will
then analyze the captured packets and extract meaningful information from the analyzed
data using the Google Speech API. Finally, we will address the causes of these vulnerabilities
and possible solutions to address them.* <br>

<br>

 * [Security Exposure of RTP packet in VoIP](https://www.koreascience.or.kr/article/JAKO201925462477952.page)

   Lee, Dong-Geon (Dept. of Computer Science, KwangWoon University); Choi, WoongChul (Dept. of Computer Science, KwangWoon University)<br>
   Received : 2019.06.09 / Accepted : 2019.06.20 / Published : 2019.08.31
   > **Abstract** <br>
   > *VoIP technology is a technology for exchanging voice or video data through IP network. Various protocols are used for this technique, in particular, RTP(Real-time Transport Protocol) protocol is used to exchange voice data. In recent years, with the development of communication technology, there has been an increasing tendency of services such as "Kakao Voice Talk" to exchange voice and video data through IP network. Most of these services provide a service with security guarantee by a user authentication process and an encryption process. However, RTP protocol does not require encryption when transmitting data. Therefore, there is an exposition risk in the voice data using RTP protocol. We will present the risk of the situation where packets are sniffed in VoIP(Voice over IP) communication using RTP protocol. To this end, we configured a VoIP telephone network, applied our own sniffing tool, and analyzed the sniffed packets to show the risk that users' data could be exposed unprotected.* <br>

 
