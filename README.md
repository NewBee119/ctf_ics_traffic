# ctf_ics_traffic
工控CTF比赛工具，各种网络数据包处理脚本  
实验环境：Ubuntu 16.04 64位  
程序目录：  
1. check_middler.py        查看数据包中是否有重传的数据包，如有，表示可能遭受中间人攻击  
运行方式：python ./check_middler.py  pcapfile
  
2. ics_packet_analysis.py  数据包统计工具，统计数据包流，长度等信息  
运行方式：python ./ics_packet_analysis.py --pcapfile=pcapfile -i    
  
3. format_transfer.py      字符串转换  
运行方式：Python ./format_transfer.py  string    
  
4. try_decodings.py        解码加密字符串(from:https://github.com/nbeaver/try-decodings )    
运行方式：python ./try_decodings.py  string

参考文章:  
http://www.freebuf.com/articles/ics-articles/176868.html  
