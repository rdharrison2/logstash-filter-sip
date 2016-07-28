# encoding: utf-8
require 'spec_helper'
require "logstash/filters/sip"

describe LogStash::Filters::SIP do
  describe "basic request" do
    config <<-CONFIG
      filter {
        sip { }
      }
    CONFIG

    sample "^MREGISTER sip:rd.pexip.com SIP/2.0^MVia: SIP/2.0/TLS 10.44.100.67:9079;branch=z9hG4bK9XIoObujY5t14sqSKMZhdlRz7vy0r3gW;rport^MFrom: sip:jasmine.hatherly2@rd.pexip.com;tag=YSM3PueZin76wthf^MTo: sip:jasmine.hatherly2@rd.pexip.com^MContact: <sip:pexep_67_James135@10.44.100.67:9079;transport=tls>;expires=3600^MCall-ID: c1592328-3326-4870-9765-7fd362ae765a^MCSeq: 1533475445 REGISTER^MRoute: <sip:10.44.152.22:5061;transport=tls;lr>^MContent-Length: 0^M^M" do
      # subject is a Logstash::Event object
      insist { subject["sip_method"] } == "REGISTER"
      insist { subject["sip_cseq"] } == "1533475445 REGISTER"
      insist { subject["sip_from_uri"] } == "sip:jasmine.hatherly2@rd.pexip.com"
      insist { subject["sip_from_tag"] } == "YSM3PueZin76wthf"
      insist { subject["sip_request_uri"] } == "sip:rd.pexip.com"
      insist { subject["sip_to_uri"] } == "sip:jasmine.hatherly2@rd.pexip.com"
      insist { subject["sip_contact"] } == "<sip:pexep_67_James135@10.44.100.67:9079;transport=tls>;expires=3600"
      insist { subject["sip_contact_uri"] } == "sip:pexep_67_James135@10.44.100.67:9079;transport=tls"
      insist { subject["sip_contact_expires"] } == "3600"
      insist { subject["sip_call_id"] } == "c1592328-3326-4870-9765-7fd362ae765a"
      insist { subject["sip_headers"] } == nil
      insist { subject["sip_body"] } == nil
      insist { subject["sip_content_length"] } == 0
    end
  end

  describe "basic INVITE" do
    config <<-CONFIG
      filter {
        sip { include_keys => []
              exclude_keys => ["body", "headers"] }
      }
    CONFIG

    sample "^MINVITE sip:conference0_alias@rd.pexip.com SIP/2.0^MVia: SIP/2.0/TLS 10.44.143.13:5061;egress-zone=sipzone104415521;branch=z9hG4bKf7cce9e25d360600861875460509e56011.247e033cc39230ac57e1859f0b31c795;proxy-call-id=fcf57da6-2b76-11e6-a9db-005056a903cb;rport^MVia: SIP/2.0/TLS 10.44.10.2:5061;branch=z9hG4bK2a445c0f934e85e6d76fe9f0b338f778.1;received=10.44.10.2;rport=35991;ingress-zone=DefaultSubZone^MCall-ID: 6410edf55ca9b632@10.44.10.2^MCSeq: 100 INVITE^MContact: <sip:marta.jakubek@citi.com;opaque=user:epid:F_7QBuwnO1GEg9vlaQLiigAA;gruu>^MFrom: \"TE002\" <sip:TE002-sip@rd.pexip.com>;tag=81b7df65ad9d40db^MTo: <sip:sip.021.conference0_alias@rd.pexip.com>^MMax-Forwards: 15^MRecord-Route: <sip:proxy-call-id=fcf57da6-2b76-11e6-a9db-005056a903cb@10.44.143.13:5061;transport=tls;lr>^MRecord-Route: <sip:proxy-call-id=fcf57da6-2b76-11e6-a9db-005056a903cb@10.44.143.13:5061;transport=tls;lr>^MAllow: INVITE,ACK,CANCEL,BYE,UPDATE,INFO,OPTIONS,REFER,NOTIFY^MUser-Agent: TANDBERG/257 (TE4.1.1.273710)^MSupported: replaces,timer,gruu,path,outbound^MSession-Expires: 180^MX-TAATag: fcf57f54-2b76-11e6-a717-005056a903cb^MContent-Type: application/sdp^MContent-Length: 3305^M^Mv=0^Mo=tandberg 2 1 IN IP4 10.44.10.2^Ms=-^Mc=IN IP4 10.44.10.2^Mb=AS:1152^Mt=0 0^Mm=audio 2326 RTP/AVP 100 102 103 9 18 11 8 0 101^Mb=TIAS:64000^Ma=rtpmap:100 MP4A-LATM/90000^Ma=fmtp:100 profile-level-id=24;object=23;bitrate=64000^Ma=rtpmap:102 G7221/16000^Ma=fmtp:102 bitrate=32000^Ma=rtpmap:103 G7221/16000^Ma=fmtp:103 bitrate=24000^Ma=rtpmap:9 G722/8000^Ma=rtpmap:18 G729/8000^Ma=fmtp:18 annexb=yes^Ma=rtpmap:11 L16/16000^Ma=rtpmap:8 PCMA/8000^Ma=rtpmap:0 PCMU/8000^Ma=rtpmap:101 telephone-event/8000^Ma=fmtp:101 0-15^Ma=crypto:0 AES_CM_128_HMAC_SHA1_80 inline:hVC+Q/anjaTWFLQ+idPs5SNo4UJ0KM616KBXEZV8|2^48^Ma=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:hVC+Q/anjaTWFLQ+idPs5SNo4UJ0KM616KBXEZV8|2^48 UNENCRYPTED_SRTCP^Ma=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:7SdGF/M1MHr77qYQcj/QyxdhZO3FY6CI4dlYFCma|2^48^Ma=sendrecv^Mm=video 2328 RTP/AVP 97 98 99 34 31^Mb=TIAS:1152000^Ma=rtpmap:97 H264/90000^Ma=fmtp:97 profile-level-id=42800d;max-br=906;max-mbps=40500;max-fs=1344;max-smbps=40500;max-fps=3000^Ma=rtpmap:98 H264/90000^Ma=fmtp:98 profile-level-id=42800d;max-br=906;max-mbps=40500;max-fs=1344;max-smbps=40500;packetization-mode=1;max-fps=3000^Ma=rtpmap:99 H263-1998/90000^Ma=fmtp:99 custom=1024,768,4;custom=1024,576,4;custom=800,600,4;cif4=2;custom=720,480,2;custom=640,480,2;custom=512,288,1;cif=1;custom=352,240,1;qcif=1;maxbr=10880^Ma=rtpmap:34 H263/90000^Ma=fmtp:34 cif4=2;cif=1;qcif=1;maxbr=10880^Ma=rtpmap:31 H261/90000^Ma=fmtp:31 cif=1;qcif=1;maxbr=10880^Ma=rtcp-fb:* nack pli^Ma=crypto:0 AES_CM_128_HMAC_SHA1_80 inline:TEjucVn04M6FxGXM5cn5sbImGzw90f48+Aykqp96|2^48^Ma=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:TEjucVn04M6FxGXM5cn5sbImGzw90f48+Aykqp96|2^48 UNENCRYPTED_SRTCP^Ma=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:3zumNjJDb8v2QqlpJXVbB8iYe40mJkfpiZ/6wPr3|2^48^Ma=sendrecv^Ma=content:main^Ma=label:11^Ma=answer:full^Mm=application 5070 UDP/BFCP *^Ma=floorctrl:c-s^Ma=confid:1^Ma=floorid:2 mstrm:12^Ma=userid:2^Ma=setup:actpass^Ma=connection:new^Mm=video 2330 RTP/AVP 97 98 99 34 31^Mb=TIAS:1152000^Ma=rtpmap:97 H264/90000^Ma=fmtp:97 profile-level-id=42800d;max-br=906;max-mbps=40500;max-fs=1344;max-smbps=40500;max-fps=3000^Ma=rtpmap:98 H264/90000^Ma=fmtp:98 profile-level-id=42800d;max-br=906;max-mbps=40500;max-fs=1344;max-smbps=40500;packetization-mode=1;max-fps=3000^Ma=rtpmap:99 H263-1998/90000^Ma=fmtp:99 custom=1024,768,4;custom=1024,576,4;custom=800,600,4;cif4=2;custom=720,480,2;custom=640,480,2;custom=512,288,1;cif=1;custom=352,240,1;qcif=1;maxbr=10880^Ma=rtpmap:34 H263/90000^Ma=fmtp:34 cif4=2;cif=1;qcif=1;maxbr=10880^Ma=rtpmap:31 H261/90000^Ma=fmtp:31 cif=1;qcif=1;maxbr=10880^Ma=rtcp-fb:* nack pli^Ma=crypto:0 AES_CM_128_HMAC_SHA1_80 inline:HbFGuJY+M3sgyx8SyO3YpFtgkhOmf1o/LgizZ+vZ|2^48^Ma=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:HbFGuJY+M3sgyx8SyO3YpFtgkhOmf1o/LgizZ+vZ|2^48 UNENCRYPTED_SRTCP^Ma=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:Elw7mLe64kO5qTpST+ZPSMvX9QXDa3FYMEcTiYpO|2^48^Ma=sendrecv^Ma=content:slides^Ma=label:12^Mm=application 2332 RTP/AVP 104^Ma=rtpmap:104 H224/4800^Ma=crypto:0 AES_CM_128_HMAC_SHA1_80 inline:L6PrWLxKnCsNhhHIHkOm9w4bSxA5UogxQZ69/8ZR|2^48^Ma=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:L6PrWLxKnCsNhhHIHkOm9w4bSxA5UogxQZ69/8ZR|2^48 UNENCRYPTED_SRTCP^Ma=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:gj6cJkqCAzNoVP3bb/m6yeUU34ZayKhLyYe8DWAF|2^48^Ma=sendrecv^M" do
      # subject is a Logstash::Event object
      #insist { subject.to_json } == "FOO"
      insist { subject["sip_method"] } == "INVITE"
      insist { subject["sip_cseq"] } == "100 INVITE"
      insist { subject["sip_from_uri"] } == 'sip:TE002-sip@rd.pexip.com'
      insist { subject["sip_from_display_name"] } == 'TE002'
      insist { subject["sip_from_tag"] } == '81b7df65ad9d40db'
      insist { subject["sip_request_uri"] } == 'sip:conference0_alias@rd.pexip.com'
      insist { subject["sip_to_uri"] } == 'sip:sip.021.conference0_alias@rd.pexip.com'
      insist { subject["sip_to_display_name"] } == nil
      insist { subject["sip_contact_uri"] } == 'sip:marta.jakubek@citi.com;opaque=user:epid:F_7QBuwnO1GEg9vlaQLiigAA;gruu'
      insist { subject["sip_call_id"] } == '6410edf55ca9b632@10.44.10.2'
      insist { subject["sip_headers"] } == nil
      insist { subject["sip_body"] } == nil
      insist { subject["sip_content_length"] } == 3305
    end
  end

  describe "basic response" do
    config <<-CONFIG
      filter {
        sip {
        }
      }
    CONFIG

    sample "^MSIP/2.0 200 OK^MVia: SIP/2.0/TLS 10.44.100.78:9898;branch=z9hG4bKx0oUBbjdPTiMQ71X32rmpGL9hWz6Jwga;rport=52818;received=10.44.100.78^MFrom: \"odelia\" <sip:odelia.lowstetter3@rd.pexip.com>;tag=t2PzhFNSpjT0ms8K^MTo:  <sip:odelia.lowstetter3@rd.pexip.com>;epid=DEB027A081;tag=835c8d3e82^MCSeq: 200774393 REGISTER^MCall-ID: b985e2cf-6166-415e-821c-92c705bc9c2c^MDate: Fri, 03 Jun 2016 09:20:01 GMT^MContact:  <sip:pexep_78_Michael198@10.44.100.78:9898;transport=tls>;expires=253^MAllow: INVITE,ACK,OPTIONS,CANCEL,BYE,REGISTER,INFO,SUBSCRIBE,NOTIFY,MESSAGE^MSupported: categoryList,adhoclist,sdp-anat,replaces^MContent-Length: 0^M^M" do
      # subject is a Logstash::Event object
      insist { subject["sip_status_code"] } == 200
      insist { subject["sip_status_reason"] } == "OK"
      insist { subject["sip_cseq"] } == "200774393 REGISTER"
      insist { subject["sip_from_uri"] } == "sip:odelia.lowstetter3@rd.pexip.com"
      insist { subject["sip_from_tag"] } == "t2PzhFNSpjT0ms8K"
      insist { subject["sip_to_uri"] } == "sip:odelia.lowstetter3@rd.pexip.com"
      insist { subject["sip_to_tag"] } == "835c8d3e82"
      insist { subject["sip_to_epid"] } == "DEB027A081"
      insist { subject["sip_call_id"] } == "b985e2cf-6166-415e-821c-92c705bc9c2c"
      insist { subject["sip_contact"] } == "<sip:pexep_78_Michael198@10.44.100.78:9898;transport=tls>;expires=253"
      insist { subject["sip_headers"] } == nil
      insist { subject["sip_body"] } == nil
      insist { subject["sip_content_length"] } == 0
    end
  end

  describe "can change included keys" do
    config <<-CONFIG
      filter {
        sip {
          include_keys => [
           "method", "request_uri",
           "content_length",
           "call_id",
           "user_agent", "headers", "body"]
        }
      }
    CONFIG

    sample "INVITE sip:8892192371@10.44.101.22 SIP/2.0^MVia: SIP/2.0/TLS 10.44.100.69:7108;branch=z9hG4bKyI2E1cF59OftJwrDmeCSTL0uiYaKjkQb;rport^MFrom: sip:pexep_69_James6@vp.pexip.com;tag=rs4BoZOV1XiPQAm8^MTo: sip:8892192371@10.44.101.22^MCSeq: 1010607896 INVITE^MCall-ID: 0c613c08-f825-4313-a893-4e7a018020fb^MUser-Agent: PexepV2/13 (31022.0.0 (1d89ceaf5b7a19c3af4c7e72e466dd1de1deea22) built by pexbot on 2016-07-26T14:56:47Z from master)^MSupported: categoryList,adhoclist^MAllow: INVITE,ACK,OPTIONS,CANCEL,BYE,REGISTER,INFO,SUBSCRIBE,NOTIFY,MESSAGE,SERVICE^MMax-Forwards: 70^MContact: <sip:pexep_69_James6@10.44.100.69:7108;transport=tls>^MRoute: <sip:10.44.101.22:5061;transport=tls;lr>^MContent-Type: application/sdp^M^Mv=0^Mo=- 1 2 IN IP4 127.0.0.1^Ms=-^Mb=AS:64^Mt=0 0^Mm=audio 22496 RTP/AVP 101 99^Mc=IN IP4 10.44.100.69^Ma=rtpmap:101 MP4A-LATM/90000^Ma=fmtp:101 bitrate=64000;profile-level-id=24;object=23^Ma=rtpmap:99 telephone-event/8000^Ma=fmtp:99 events=0-15^Ma=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:z417GA+iRAxUX/joYilNnm5ujuGyQ1bc1Z9Zj+QN|2^48^Ma=sendrecv^Mm=application 22498 UDP/BFCP *^Mc=IN IP4 10.44.100.69^Ma=bfcpver:1^Ma=floorctrl:c-only^Ma=sendrecv^M" do
      # subject is a Logstash::Event object
      insist { subject["sip_method"] } == "INVITE"
      insist { subject["sip_cseq"] } == nil
      insist { subject["sip_from_uri"] } == nil
      insist { subject["sip_from_display_name"] } == nil
      insist { subject["sip_from_tag"] } == nil
      insist { subject["sip_request_uri"] } == "sip:8892192371@10.44.101.22"
      insist { subject["sip_user_agent"] } == "PexepV2/13 (31022.0.0 (1d89ceaf5b7a19c3af4c7e72e466dd1de1deea22) built by pexbot on 2016-07-26T14:56:47Z from master)"
      insist { subject["sip_to_uri"] } == nil
      insist { subject["sip_to_display_name"] } == nil
      insist { subject["sip_contact_uri"] } == nil
      insist { subject["sip_call_id"] } == "0c613c08-f825-4313-a893-4e7a018020fb"
      insist { subject["sip_contact"] } == nil
      insist { subject["sip_headers"] } == "Via: SIP/2.0/TLS 10.44.100.69:7108;branch=z9hG4bKyI2E1cF59OftJwrDmeCSTL0uiYaKjkQb;rport\nFrom: sip:pexep_69_James6@vp.pexip.com;tag=rs4BoZOV1XiPQAm8\nTo: sip:8892192371@10.44.101.22\nCSeq: 1010607896 INVITE\nCall-ID: 0c613c08-f825-4313-a893-4e7a018020fb\nUser-Agent: PexepV2/13 (31022.0.0 (1d89ceaf5b7a19c3af4c7e72e466dd1de1deea22) built by pexbot on 2016-07-26T14:56:47Z from master)\nSupported: categoryList,adhoclist\nAllow: INVITE,ACK,OPTIONS,CANCEL,BYE,REGISTER,INFO,SUBSCRIBE,NOTIFY,MESSAGE,SERVICE\nMax-Forwards: 70\nContact: <sip:pexep_69_James6@10.44.100.69:7108;transport=tls>\nRoute: <sip:10.44.101.22:5061;transport=tls;lr>\nContent-Type: application/sdp"
      insist { subject["sip_body"] } == "v=0\no=- 1 2 IN IP4 127.0.0.1\ns=-\nb=AS:64\nt=0 0\nm=audio 22496 RTP/AVP 101 99\nc=IN IP4 10.44.100.69\na=rtpmap:101 MP4A-LATM/90000\na=fmtp:101 bitrate=64000;profile-level-id=24;object=23\na=rtpmap:99 telephone-event/8000\na=fmtp:99 events=0-15\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:z417GA+iRAxUX/joYilNnm5ujuGyQ1bc1Z9Zj+QN|2^48\na=sendrecv\nm=application 22498 UDP/BFCP *\nc=IN IP4 10.44.100.69\na=bfcpver:1\na=floorctrl:c-only\na=sendrecv\n"
      insist { subject["sip_content_length"] } == 449
    end
  end


end
