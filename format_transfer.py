#!/usr/bin/python
#coding:utf-8

coils_bytes = 'c29e46a64eeaf64e3626c2ae0ec2a22ac24c0c8c1c'.decode('hex')
print len(coils_bytes)
flag = ''
for data in coils_bytes:
        #print int('{:08b}'.format(ord(data)))
        #print int('{:08b}'.format(ord(data)), 2)
        #print int('{:08b}'.format(ord(data))[::-1])
        #print int('{:08b}'.format(ord(data))[::-1], 2)
	#print int('{:08b}'.format(ord(data)),2),int('{:08b}'.format(ord(data))[::-1], 2)
	flag += chr(int('{:08b}'.format(ord(data))[::-1], 2))
print flag
