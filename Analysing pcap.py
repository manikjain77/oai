
obj = {
    '192.168.70.133' : 'SMF',
    '192.168.70.134' : 'UPF',
    '192.168.70.138': 'AUSF',
    '192.168.70.137': 'UDM',
    '192.168.70.132': 'AMF',
    '192.168.70.136': 'UDR',
    '192.168.70.130': 'NRF'
}




#  AMF 
# ip.src == 192.168.70.151 and ip.dst == 192.168.70.132 and frame.len == 146 and ngap.procedureCode == 21, +4
# (ip.addr == 192.168.70.151) && (ngap.procedureCode == 4) and frame.len == 146,+1
# ip.addr == 192.168.70.151 and ngap.procedureCode == 4 and frame.len == 126, +1
# (ip.src == 192.168.70.132 ) && (ngap.procedureCode == 14) && (ip.dst == 192.168.70.151)
# (ngap.procedureCode == 46) && (frame.len == 238) && (ip.src == 192.168.70.151)


import pyshark

# Define the filter expression

# SUPI = [208950000000093,208950000000094,208950000000095,208950000000096,208950000000097,208950000000098,208950000000099,208950000000100,208950000000101,208950000000102]
# IP = ['192.168.70.143','192.168.70.144','192.168.70.145','192.168.70.146','192.168.70.147','192.168.70.148','192.168.70.149','192.168.70.150','192.168.70.151','192.168.70.152']


mp = {}
SUPI = [208950000000093]
IP = ['192.168.70.143']
_file = '1_2_3.pcap'
times = []
pckts = []
ip = IP[0]
supi = SUPI[0]
capture = pyshark.FileCapture(_file, display_filter=f'(ngap.procedureCode == 15) and ip.src == {ip}')
for packet in capture:
    pcktno = int(packet.number)
    pckts.append(pcktno)
    print("Frame Relative Time:",pcktno)
capture.close()

pckts.append(pckts[-1]*10)

RR = []
for i in range(len(pckts)-1):
    _time = []
    all = f' and frame.number >= {pckts[i]} and frame.number < {pckts[i+1]}'
    part1 = f'ip.src == {ip}  and ngap.procedureCode == 15'+all  
    part1_1 = f'ip.addr == {ip} and (sctp.sack_cumulative_tsn_ack == 0)'+all
    # Authentication request
    part2 = f'ip.addr == {ip} and nas-5gs.mm.message_type == 0x56 and frame.number < {pckts[i+1]}'+all
    # Authentication response
    part2_1 = f'ip.addr == {ip} and nas-5gs.mm.message_type == 0x57'+all

    # Security mode command (nas-5gs.mm.message_type == 0x5d)
    part_3 = f'ip.addr == {ip} and nas-5gs.mm.message_type == 0x5d'+all
    part_3_1 = f'(ip.addr eq 192.168.70.143 ) && (ngap.procedureCode == 46)'+all
    # InitialContextSetupRequest
    part4 = f'ip.addr == 192.168.70.143 && (ngap.protocolIEs == 9)'+all
    # InitialContextSetupResponse
    part4_1 = f'ip.addr == 192.168.70.143 && (ngap.protocolIEs == 2)'+all


    part5 = f'(ngap.procedureCode == 46 and frame.number <= {pckts[i+1]}) '

    pcktno = 0
    time1_start = 0.0
    time1_end = 0.0
    # capture = pyshark.FileCapture(_file, display_filter=part1)
    # for packet in capture:
    #     frame_relative_time = packet.frame_info.time_relative
    #     pcktno = int(packet.number)
    #     time1_start = float(frame_relative_time)
    #     print("Frame Relative Time:", frame_relative_time)
    # capture.close()
    
    # capture = pyshark.FileCapture(_file, display_filter= part1_1)
    # for packet in capture:
    #     # Extract and display frame.relative_time
    #     frame_relative_time = packet.frame_info.time_relative
    #     time1_end = float(frame_relative_time)
    #     print("Frame Relative Time:", frame_relative_time)
    # # Close the capture
    # capture.close()
    # print("AMF-GNB")
    # print("Step-1")
    # print(time1_end-time1_start)
    # print(pcktno)
    # mp[pcktno] = 'AMF-GNB-1'
    # _time.append([pcktno,time1_end-time1_start])

    capture = pyshark.FileCapture(_file, display_filter=part2)
    for packet in capture:
        # Extract and display frame.relative_time
        frame_relative_time = packet.frame_info.time_relative
        pcktno = int(packet.number)
        time1_start = float(frame_relative_time)
        print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()

    capture = pyshark.FileCapture(_file, display_filter= part2_1)
    for packet in capture:
        # Extract and display frame.relative_time
        frame_relative_time = packet.frame_info.time_relative
        time1_end = float(frame_relative_time)
        print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()
    print("Step-2")
    
    print(time1_end-time1_start)
    print(pcktno)
    mp[pcktno] = 'AMF-GNB-2'
    _time.append([pcktno,time1_end-time1_start])
    

    capture = pyshark.FileCapture(_file, display_filter=part_3)
    for packet in capture:
        # Extract and display frame.relative_time
        frame_relative_time = packet.frame_info.time_relative
        pcktno = int(packet.number)
        time1_start = float(frame_relative_time)
        print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()
    print(pcktno)
    capture = pyshark.FileCapture(_file, display_filter= part_3_1 +f' and frame.number >= {pcktno}')
    ii = 0
    for packet in capture:
        # Extract and display frame.relative_time
        if ii == 0:
            frame_relative_time = packet.frame_info.time_relative
            time1_end = float(frame_relative_time)
            print("Frame Relative Time:", frame_relative_time)
        else:
            break
        ii += 1
    # Close the capture
    capture.close()
    print("Step-3")
    
    print(time1_end-time1_start)
    print(pcktno)
    mp[pcktno] = 'AMF-GNB-3'
    _time.append([pcktno,time1_end-time1_start])


    capture = pyshark.FileCapture(_file, display_filter=part4)
    for packet in capture:
        # Extract and display frame.relative_time
        frame_relative_time = packet.frame_info.time_relative
        pcktno = int(packet.number)
        time1_start = float(frame_relative_time)
        print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()
    LL = 0
    capture = pyshark.FileCapture(_file, display_filter= part4_1)
    for packet in capture:
        # Extract and display frame.relative_time
        frame_relative_time = packet.frame_info.time_relative
        LL = int(packet.number)
        time1_end = float(frame_relative_time)
        print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()
    print("Step-4")
    
    print(time1_end-time1_start)
    print(pcktno)
    mp[pcktno] = 'AMF-GNB-4'
    _time.append([pcktno,time1_end-time1_start])

    pcktno = -1
    capture = pyshark.FileCapture(_file, display_filter=part5 + f' and frame.number >= {LL}')
    for packet in capture:
        # Extract and display frame.relative_time
        if pcktno == -1:
            frame_relative_time = packet.frame_info.time_relative
            pcktno = int(packet.number)
            time1_start = float(frame_relative_time)
            print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()

    capture = pyshark.FileCapture(_file, display_filter= f'frame.number == {pckts[i]}')
    for packet in capture:
        # Extract and display frame.relative_time
        frame_relative_time = packet.frame_info.time_relative
        pcktno = int(packet.number)
        time1_end = float(frame_relative_time)
        print("Frame Relative Time:", frame_relative_time)
    # Close the capture
    capture.close()
    print("Step-5")
    
    print(-1*time1_end+time1_start)
    print(pcktno-1)
    # mp[pcktno-1] = 'AMF-GNB-5'
    # _time.append([pcktno-1,-1*time1_end+time1_start])
    RR.append(-1*time1_end+time1_start)

    # filter_string = f'(ngap.procedureCode == 21) && (frame.len == 146) && (ip.src == {ip}) and frame.number >= {pckts[i]} and frame.number < {pckts[i+1]}'

    # # Open the PCAP file
    # capture = pyshark.FileCapture(_file, display_filter=filter_string)
    # start_no = 0
    # end_no = 0
    # start = ""
    # for packet in capture:
    #     # Extract and display frame.relative_time
    #     frame_relative_time = packet.frame_info.time_relative
    #     start_no = int(packet.number)
    #     start = float(frame_relative_time)
    #     print("Frame Relative Time:", frame_relative_time)
    # # Close the capture
    # capture.close()

    # filter_string = f'(ngap.procedureCode == 46) && (frame.len == 238 or frame.len == 242) && (ip.src == {ip}) and frame.number >= {pckts[i]} and frame.number < {pckts[i+1]}'
    # end = 0.0
    # # Open the PCAP file
    # capture = pyshark.FileCapture(_file, display_filter=filter_string)

    # for packet in capture:
    #     # Extract and display frame.relative_time
    #     frame_relative_time = packet.frame_info.time_relative
    #     end = float(frame_relative_time)
    #     end_no = int(packet.number)
    #     print("Frame Relative Time:", frame_relative_time)
    # # Close the capture
    # capture.close()
    # print("REgistration Time : ", end - start)
    # (http.request.uri.path contains 208950000000101) or http2.headers.path contains 208950000000101 or json.value.string == "208950000000101"
    
    print("====================================================================")
    
    filter_expression = f'(http2.headers.path contains {supi} or json.value.string == "{supi}" or http.request.uri.path contains {supi} or (http2.header.value contains ccefd90c-d8c9-4255-8977-e2d1133dfaad and frame.len == 163))and frame.number >= {pckts[i]} and frame.number < {pckts[i+1]}'

    capture = pyshark.FileCapture(_file, display_filter=filter_expression)
    # Dictionary to store the last relative_time value for each TCP stream
    stream_last_relative_time = {}

    # Dictionary to store source IP and destination IP for each TCP stream
    stream_ips = {}
    tot = 0.0
    mn = float('inf')
    mx = 0

    # Process the filtered packets
    for packet in capture:
        try:
            if 'TCP' in packet:
                stream = packet.tcp.stream
                current_time = float(packet.tcp.time_relative)
                
                stream_last_relative_time[stream] = current_time
                packet_number = int(packet.number)
                if stream not in stream_ips:
                    stream_ips[stream] = {'source_ip': packet.ip.src, 'dest_ip': packet.ip.dst}
        except AttributeError as e:
            print(f'Error accessing packet details: {e}')
    
    capture.close()
    res = {}
    res2 = {}
    start_ = {}
    for stream, last_relative_time in stream_last_relative_time.items():
        capture = pyshark.FileCapture(_file, display_filter=f'tcp.stream eq {stream}')
        for packet in capture:
            try:
                if 'TCP' in packet:
                    stream = packet.tcp.stream
                    current_time = float(packet.tcp.time_relative)
                    
                    # Update the last relative time for the TCP stream
                    if stream not in start_:
                        start_[stream] =  int(packet.number)
                    res[stream] = current_time
                    res2[stream] = int(packet.number)
                    if stream not in stream_ips:
                        stream_ips[stream] = {'source_ip': packet.ip.src, 'dest_ip': packet.ip.dst}
            except AttributeError as e:
                print(f'Error accessing packet details: {e}')
        capture.close()

    # Print the supi and summary information
    print(supi)
    i = 0
    print("Registration")
    for stream, last_relative_time in stream_last_relative_time.items():
        source_ip = stream_ips[stream]['source_ip']
        dest_ip = stream_ips[stream]['dest_ip']
        i += 1
        if i == 11:
            continue
        
        _time.append([start_[stream],res[stream]])
        mp[start_[stream]] = f'{obj[source_ip]} - {obj[dest_ip]}'
        print(f'Step: {i}, {obj[source_ip]} <--------> {obj[dest_ip]}, Last Relative Time: {res[stream]}, Stream: {stream}')
        if i != 11:
            tot += last_relative_time
    print(_time)
    _time.sort(key=lambda row: row[0])
    times.append(_time)
    print(f'Total time: {tot}')
    

print(times)
print(mp)
'''
mp = {439: 'AMF-GNB-1', 533: 'AMF-GNB-2', 617: 'AMF-GNB-3', 627: 'AMF-GNB-4', 629: 'AMF-GNB-5', 532: 'AMF - AUSF', 525: 'AUSF - UDM', 497: 'UDM - UDR', 519: 'UDM - UDR', 613: 'AUSF - UDM', 582: 'UDM - UDR', 611: 'UDM - UDR', 616: 'AUSF - AMF', 626: 'AMF - UDM', 1437: 'AMF-GNB-1', 1555: 'AMF-GNB-2', 1656: 'AMF-GNB-3', 1668: 'AMF-GNB-4', 1669: 'AMF-GNB-5', 1558: 'AMF - AUSF', 1547: 'AUSF - UDM', 1515: 'UDM - UDR', 1545: 'UDM - UDR', 1653: 'AUSF - UDM', 1621: 'UDM - UDR', 1644: 'UDM - UDR', 1655: 'AUSF - AMF', 1667: 'AMF - UDM', 2217: 'AMF-GNB-1', 2330: 'AMF-GNB-2', 2415: 'AMF-GNB-3', 2428: 'AMF-GNB-4', 2438: 'AMF-GNB-5', 2332: 'AMF - AUSF', 2328: 'AUSF - UDM', 2297: 'UDM - UDR', 2323: 'UDM - UDR', 2410: 'AUSF - UDM', 2381: 'UDM - UDR', 2408: 'UDM - UDR', 2414: 'AUSF - AMF', 2427: 'AMF - UDM', 3255: 'AMF-GNB-1', 3348: 'AMF-GNB-2', 3426: 'AMF-GNB-3', 3440: 'AMF-GNB-4', 3442: 'AMF-GNB-5', 3345: 'AMF - AUSF', 3347: 'AUSF - UDM', 3311: 'UDM - UDR', 3335: 'UDM - UDR', 3430: 'AUSF - UDM', 3395: 'UDM - UDR', 3417: 'UDM - UDR', 3428: 'AUSF - AMF', 3439: 'AMF - UDM', 4212: 'AMF-GNB-1', 4342: 'AMF-GNB-2', 4431: 'AMF-GNB-3', 4442: 'AMF-GNB-4', 4444: 'AMF-GNB-5', 4344: 'AMF - AUSF', 4346: 'AUSF - UDM', 4311: 'UDM - UDR', 4335: 'UDM - UDR', 4426: 'AUSF - UDM', 4395: 'UDM - UDR', 4418: 'UDM - UDR', 4430: 'AUSF - AMF', 4441: 'AMF - UDM', 5079: 'AMF-GNB-1', 5190: 'AMF-GNB-2', 5275: 'AMF-GNB-3', 5287: 'AMF-GNB-4', 5308: 'AMF-GNB-5', 5192: 'AMF - AUSF', 5189: 'AUSF - UDM', 5154: 'UDM - UDR', 5181: 'UDM - UDR', 5274: 'AUSF - UDM', 5239: 'UDM - UDR', 5272: 'UDM - UDR', 5270: 'AUSF - AMF', 5286: 'AMF - UDM', 6114: 'AMF-GNB-1', 6196: 'AMF-GNB-2', 6282: 'AMF-GNB-3', 6298: 'AMF-GNB-4', 6306: 'AMF-GNB-5', 6202: 'AMF - AUSF', 6200: 'AUSF - UDM', 6167: 'UDM - UDR', 6198: 'UDM - UDR', 6286: 'AUSF - UDM', 6254: 'UDM - UDR', 6277: 'UDM - UDR', 6284: 'AUSF - AMF', 6297: 'AMF - UDM', 7135: 'AMF-GNB-1', 7227: 'AMF-GNB-2', 7305: 'AMF-GNB-3', 7321: 'AMF-GNB-4', 7331: 'AMF-GNB-5', 7226: 'AMF - AUSF', 7224: 'AUSF - UDM', 7191: 'UDM - UDR', 7222: 'UDM - UDR', 7311: 'AUSF - UDM', 7276: 'UDM - UDR', 7307: 'UDM - UDR', 7309: 'AUSF - AMF', 7320: 'AMF - UDM', 7924: 'AMF-GNB-1', 8058: 'AMF-GNB-2', 8143: 'AMF-GNB-3', 8161: 'AMF-GNB-4', 8171: 'AMF-GNB-5', 8064: 'AMF - AUSF', 8062: 'AUSF - UDM', 8027: 'UDM - UDR', 8060: 'UDM - UDR', 8149: 'AUSF - UDM', 8111: 'UDM - UDR', 8145: 'UDM - UDR', 8147: 'AUSF - AMF', 8160: 'AMF - UDM', 8949: 'AMF-GNB-1', 9036: 'AMF-GNB-2', 9123: 'AMF-GNB-3', 9133: 'AMF-GNB-4', 9137: 'AMF-GNB-5', 9038: 'AMF - AUSF', 9040: 'AUSF - UDM', 9003: 'UDM - UDR', 9027: 'UDM - UDR', 9122: 'AUSF - UDM', 9087: 'UDM - UDR', 9110: 'UDM - UDR', 9120: 'AUSF - AMF', 9132: 'AMF - UDM'}
times = [[[439, 0.0006813180000015961], [497, 0.006519934], [519, 0.015424182], [525, 0.030904733], [532, 0.044359434], [533, 0.0048460659999989275], [582, 0.008920283], [611, 0.021830943], [613, 0.036539475], [616, 0.043423394], [617, 0.007400172999997068], [626, 0.000593002], [627, 0.0011451790000016615], [629, 7.929200000234005e-05]], [[1437, 0.006163104000002306], [1515, 0.007617095], [1545, 0.012040533], [1547, 0.028622974], [1555, 0.0039370420000039985], [1558, 0.080212345], [1621, 0.007349933], [1644, 0.010782934], [1653, 0.043901002], [1655, 0.052260383], [1656, 0.0007747399999971094], [1667, 0.002516234], [1668, 0.0002496779999958676], [1669, 8.308799999667826e-05]], [[2217, 0.0016224109999996017], [2297, 0.002333245], [2323, 0.018958389], [2328, 0.027500656], [2330, 0.0025411450000092373], [2332, 0.040216926], [2381, 0.001951708], [2408, 0.00541411], [2410, 0.010659178], [2414, 0.022348157], [2415, 0.00928730200000416], [2427, 0.0065869], [2428, 0.004000881999999706], [2438, 0.00015150899999127887]], [[3255, 0.0019754120000072817], [3311, 0.004134343], [3335, 0.012590279], [3345, 0.025339293], [3347, 0.025436303], [3348, 0.012609202999996683], [3395, 0.003525049], [3417, 0.012245159], [3426, 0.00011242600000116454], [3428, 0.028001441], [3430, 0.023137758], [3439, 0.001764339], [3440, 0.011763709999996763], [3442, 8.292799999765066e-05]], [[4212, 0.0004499820000063437], [4311, 0.00260019], [4335, 0.009961182], [4342, 0.007899570000006406], [4344, 0.024454808], [4346, 0.018308705], [4395, 0.005454075], [4418, 0.007035252], [4426, 0.021891262], [4430, 0.025520773], [4431, 0.0062973189999979695], [4441, 0.002370748], [4442, 0.0009560029999988728], [4444, 5.532499997684681e-05]], [[5079, 0.000922459999998182], [5154, 0.003614131], [5181, 0.009650919], [5189, 0.034299551], [5190, 0.007947308000012754], [5192, 0.042818771], [5239, 0.003735457], [5270, 0.030268448], [5272, 0.009229631], [5274, 0.02208712], [5275, 0.010333965000000944], [5286, 0.000953178], [5287, 0.00031065099997817924], [5308, 7.015200000637378e-05]], [[6114, 0.0011211199999934252], [6167, 0.003562283], [6196, 0.001990410000018983], [6198, 0.012858727], [6200, 0.02340008], [6202, 0.028154849], [6254, 0.004019119], [6277, 0.01152931], [6282, 0.0004021459999989929], [6284, 0.034314337], [6286, 0.027452394], [6297, 0.0011839], [6298, 0.000569777000009708], [6306, 0.00012767699999471915]], [[7135, 0.0032351779999828523], [7191, 0.005089381], [7222, 0.028264681], [7224, 0.042576634], [7226, 0.059202301], [7227, 0.0009068469999817808], [7276, 0.004292058], [7305, 0.000696858999987171], [7307, 0.03170466], [7309, 0.054846444], [7311, 0.052938991], [7320, 0.000962208], [7321, 0.001982274999988931], [7331, 0.0006231890000094609]], [[7924, 0.00045300599998654434], [8027, 0.002305511], [8058, 0.015114334000003282], [8060, 0.009291073], [8062, 0.018741791], [8064, 0.02452702], [8111, 0.001455892], [8143, 0.00037522200000239536], [8145, 0.009011545], [8147, 0.015969295], [8149, 0.013429451], [8160, 0.000486101], [8161, 0.006676338999994869], [8171, 9.771799997793096e-05]], [[8949, 0.0005991029999847797], [9003, 0.003281405], [9027, 0.006762897], [9036, 0.007124878000013268], [9038, 0.015669498], [9040, 0.01455768], [9087, 0.003135844], [9110, 0.010396336], [9120, 0.021271238], [9122, 0.018674674], [9123, 0.008337325000013607], [9132, 0.000800372], [9133, 0.00035795600001620187], [9137, 6.053599997812853e-05]]]

'''


import pandas as pd
ar = []
data = {
}


print(len(times[0]))
for i in range(len(times[0])):
    ar.append(mp[times[0][i][0]])
ar.append("Total Time")
while(len(ar) < 13):
    ar.append(0)
data['Steps'] = ar
for i in range(len(times)):
    s = "Registration "+ str(i+1)
    ar = []
    for [x,y] in times[i]:
        ar.append(y)
    ar.append(RR[i])
    while len(ar) < 13:
        ar.append(-1)
    data[s] = ar


# Create a DataFrame
df = pd.DataFrame(data)


# Save DataFrame to Excel file
df.to_excel('example_35.xlsx', index=False)
    

import matplotlib.pyplot as plt
for arr in times:
# Example arrays of x and y values

    x_values = []
    y_values = []
    for [i,j] in arr:
        y_values.append(j)
    for i in range(1,len(arr)+1):
        x_values.append(i)

    # Plot the scatter plot
    plt.scatter(x_values, y_values)

    # Adding labels and title
    plt.xlabel('Registration Steps')
    plt.ylabel('Time (in sec)')
    f = _file.split('.')
    title = f[0].split('_')
    plt.title(title[0]+ ' Registration samples with '+ title[1]+'sec Probing time with ' + title[2]+' Attackers')

# Show the pl

# Show the plot
plt.show()
_times = []
for i in range(len(times)):
    time = []
    for j in range(len(times[i])):
        time.append(times[i][j][1])
    while(len(time)<13):
        time.append(0)

    _times.append(time)
transposed_array = [[_times[j][i] for j in range(len(_times))] for i in range(len(_times[0]))]
print(transposed_array)
plt.boxplot(transposed_array)
plt.xlabel('Registration Steps')
plt.ylabel('Time (in sec)')
plt.title(title[0]+ ' Registration samples with '+ title[1]+'sec Probing time with ' + title[2]+' Attackers')
plt.show()




print(RR)


# import pandas as pd

# # Example data
# data = {
#     'Steps': ['AMF-GNB Step-1','AMF-GNB Step-2','AMF-GNB Step-3','AMF-GNB Step-4','AMF-GNB Step-5', 'AMF - AUSF', 'AUSF - UDM','UDM - UDR','UDM - UDR','AUSF - UDM','UDM - UDR','UDM - UDR','AUSF - AMF','AMF - UDM'],
# }

# # Create a DataFrame
# df = pd.DataFrame(data)

# # Save DataFrame to Excel file
# df.to_excel('example.xlsx', index=False)
    

# import matplotlib.pyplot as plt
# for arr in times:
# # Example arrays of x and y values

#     x_values = []
#     y_values = arr
#     for i in range(1,len(arr)+1):
#         x_values.append(i)

#     # Plot the scatter plot
#     plt.scatter(x_values, y_values)

#     # Adding labels and title
#     plt.xlabel('Registration Steps')
#     plt.ylabel('Time (in sec)')
#     title = _file.split('_')
#     plt.title(title[0]+ ' Registration samples with '+ title[1]+'sec Probing time with ' + title[2]+' Attackers')

# # Show the pl

# # Show the plot
# plt.show()



# transposed_array = [[times[j][i] for j in range(len(times))] for i in range(len(times[0]))]
# print(transposed_array)
# plt.boxplot(transposed_array)
# plt.xlabel('Steps')
# plt.ylabel('Time')
# plt.title('Box Plot of Test Scores')
# plt.show()



# for supi,ip in zip(SUPI,IP):




#     print("==================================================================")
#     print(ip," ",supi)
#     print("==================================================================")

#     part1 = f'ip.src == {ip} and ip.dst == 192.168.70.132 and frame.len == 146 and ngap.procedureCode == 21'
#     part2 = f'(ip.addr == {ip}) && (ngap.procedureCode == 4) and frame.len == 146'
#     part3 = f'ip.addr == {ip} and ngap.procedureCode == 4 and frame.len == 126'
#     part4 = f'(ip.src == 192.168.70.132 ) && (ngap.procedureCode == 14) && (ip.dst == {ip})'
#     part5 = f'(ngap.procedureCode == 46) && (frame.len == 238 or frame.len == 242) && (ip.src == {ip})'

#     _time = []

#     # Open the PCAP file
#     pcktno = 0
#     time1_start = 0.0
#     time1_end = 0.0
#     capture = pyshark.FileCapture(_file, display_filter=part1)
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_start = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()

#     capture = pyshark.FileCapture(_file, display_filter= f'frame.number == {pcktno+3}')
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_end = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()
#     print("AMF-GNB")
#     print("Step-1")
#     print(time1_end-time1_start)
#     _time.append(time1_end-time1_start)

#     capture = pyshark.FileCapture(_file, display_filter=part2)
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_start = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()

#     capture = pyshark.FileCapture(_file, display_filter= f'frame.number == {pcktno+1}')
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_end = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()
#     print("Step-2")
    
#     print(time1_end-time1_start)
#     _time.append(time1_end-time1_start)
    

#     capture = pyshark.FileCapture(_file, display_filter=part3)
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_start = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()

#     capture = pyshark.FileCapture(_file, display_filter= f'frame.number == {pcktno+1}')
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_end = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()
#     print("Step-3")
    
#     print(time1_end-time1_start)
#     _time.append(time1_end-time1_start)


#     capture = pyshark.FileCapture(_file, display_filter=part4)
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_start = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()

#     capture = pyshark.FileCapture(_file, display_filter= f'frame.number == {pcktno+1}')
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_end = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()
#     print("Step-4")
    
#     print(time1_end-time1_start)
#     _time.append(time1_end-time1_start)


#     capture = pyshark.FileCapture(_file, display_filter=part5)
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_start = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()

#     capture = pyshark.FileCapture(_file, display_filter= f'frame.number == {pcktno-1}')
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         pcktno = int(packet.number)
#         time1_end = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()
#     print("Step-5")
    
#     print(-1*time1_end+time1_start)
#     _time.append(-1*time1_end+time1_start)


#     filter_string = f'(ngap.procedureCode == 21) && (frame.len == 146) && (ip.src == {ip})'

#     # Open the PCAP file
#     capture = pyshark.FileCapture(_file, display_filter=filter_string)
#     start_no = 0
#     end_no = 0
#     start = ""
#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         start_no = int(packet.number)
#         start = float(frame_relative_time)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()

#     filter_string = f'(ngap.procedureCode == 46) && (frame.len == 238 or frame.len == 242) && (ip.src == {ip})'
#     end = 0.0
#     # Open the PCAP file
#     capture = pyshark.FileCapture(_file, display_filter=filter_string)

#     for packet in capture:
#         # Extract and display frame.relative_time
#         frame_relative_time = packet.frame_info.time_relative
#         end = float(frame_relative_time)
#         end_no = int(packet.number)
#         print("Frame Relative Time:", frame_relative_time)
#     # Close the capture
#     capture.close()
    
#     print("REgistration Time : ", end - start)

#     # (http.request.uri.path contains 208950000000101) or http2.headers.path contains 208950000000101 or json.value.string == "208950000000101"
#     filter_expression = f'http2.headers.path contains {supi} or json.value.string == "{supi}" or http.request.uri.path contains {supi} or (http2.header.value contains ccefd90c-d8c9-4255-8977-e2d1133dfaad and frame.len == 163 and frame.number >= {start_no} and frame.number <= {end_no} )'

#     capture = pyshark.FileCapture(_file, display_filter=filter_expression)

#     # Dictionary to store the last relative_time value for each TCP stream
#     stream_last_relative_time = {}

#     # Dictionary to store source IP and destination IP for each TCP stream
#     stream_ips = {}
#     tot = 0.0
#     mn = float('inf')
#     mx = 0

#     # Process the filtered packets
#     for packet in capture:
#         try:
#             if 'TCP' in packet:
#                 stream = packet.tcp.stream
#                 current_time = float(packet.tcp.time_relative)
                
#                 # Update the last relative time for the TCP stream
#                 stream_last_relative_time[stream] = current_time
                
#                 # Update minimum and maximum packet numbers
#                 packet_number = int(packet.number)
#                 mn = min(mn, packet_number)
#                 mx = max(mx, packet_number)

#                 if stream not in stream_ips:
#                     stream_ips[stream] = {'source_ip': packet.ip.src, 'dest_ip': packet.ip.dst}
#         except AttributeError as e:
#             print(f'Error accessing packet details: {e}')
    
#     capture.close()
    
#     res = {}
#     for stream, last_relative_time in stream_last_relative_time.items():
#         capture = pyshark.FileCapture(_file, display_filter=f'tcp.stream eq {stream}')
#         for packet in capture:
#             try:
#                 if 'TCP' in packet:
#                     stream = packet.tcp.stream
#                     current_time = float(packet.tcp.time_relative)
                    
#                     # Update the last relative time for the TCP stream
#                     res[stream] = current_time
#                     if stream not in stream_ips:
#                         stream_ips[stream] = {'source_ip': packet.ip.src, 'dest_ip': packet.ip.dst}
#             except AttributeError as e:
#                 print(f'Error accessing packet details: {e}')
#         capture.close()

#     # Print the supi and summary information
#     print(supi)
#     i = 0
#     print("Registration")
#     for stream, last_relative_time in stream_last_relative_time.items():
#         source_ip = stream_ips[stream]['source_ip']
#         dest_ip = stream_ips[stream]['dest_ip']
#         i += 1
#         if i == 11:
#             continue
        
#         _time.append(res[stream])
#         print(f'Step: {i}, {obj[source_ip]} <--------> {obj[dest_ip]}, Last Relative Time: {res[stream]}, Stream: {stream}')
#         if i != 11:
#             tot += last_relative_time
#     times.append(_time)
#     print(f'Total time: {tot}')

# print(times)


# import matplotlib.pyplot as plt
# for arr in times:
# # Example arrays of x and y values

#     x_values = []
#     y_values = arr
#     for i in range(1,len(arr)+1):
#         x_values.append(i)

#     # Plot the scatter plot
#     plt.scatter(x_values, y_values)

#     # Adding labels and title
#     plt.xlabel('X Values')
#     plt.ylabel('Y Values')
#     plt.title('Scatter Plot')

# # Show the pl

# # Show the plot
# plt.show()



# transposed_array = [[times[j][i] for j in range(len(times))] for i in range(len(times[0]))]
# print(transposed_array)
# plt.boxplot(transposed_array)
# plt.xlabel('Steps')
# plt.ylabel('Time')
# plt.title('Box Plot of Test Scores')
# plt.show()

'''
    # Apply the display filter in the FileCapture constructor
    capture = pyshark.FileCapture(_file, display_filter=filter_expression)

    # Dictionary to store the relative_time value for each TCP stream
    stream_relative_time = {}

    # Dictionary to store source IP and destination IP for each TCP stream
    stream_ips = {}
    tot = 0.0
    mn = 1e18
    mx = 0
    # Process the filtered packets and print the tcp.relative_time, source IP, and destination IP for each TCP stream
    for packet in capture:
        try:
            if 'TCP' in packet:
                stream = packet.tcp.stream
                if stream not in stream_relative_time:
                    stream_relative_time[stream] = []
                stream_relative_time[stream].append(float(packet.tcp.time_relative))
                tot += float(packet.tcp.time_relative)
                mn = int(packet.number)
                mx = int(packet.number)
                if stream not in stream_ips:
                    stream_ips[stream] = {'source_ip': packet.ip.src, 'dest_ip': packet.ip.dst}
        except AttributeError as e:
            print(f'Error accessing packet details: {e}')

    # Print the tcp.relative_time, source IP, and destination IP for each TCP stream
    print(supi)
    extra = 0
    i = 0
    print("Registration")
    for stream, relative_times in stream_relative_time.items():
        source_ip = stream_ips[stream]['source_ip']
        dest_ip = stream_ips[stream]['dest_ip']
        i = i + 1
        if(i == 11):
            continue 
        print(f'Step: {i},  {obj[source_ip]} <--------> {obj[dest_ip]}, Time : {relative_times}, Stream: {stream}')
        if(i == 11):
            tot -= float(relative_times[0])
    print(tot)
    
    capture.close()

'''
# import pyshark

# # Define the filter expression
# filter_expression = 'http2.headers.path contains 208950000000101 or json.value.string == "208950000000101"'

# # Apply the display filter in the FileCapture constructor
# capture = pyshark.FileCapture(_file, display_filter=filter_expression)

# # Process the filtered packets and display the packet number, TCP stream number, src IP, and dest IP
# for packet in capture:
#     print(f'Packet Number: {packet.number}')
#     try:
#         if 'TCP' in packet:
#             print(f'TCP Stream: {packet.tcp.stream}')
#             if 'IP' in packet:
#                 print(f'Source IP: {packet.ip.src}')
#                 print(f'Destination IP: {packet.ip.dst}')
#             elif 'IPv6' in packet:
#                 print(f'Source IP: {packet.ipv6.src}')
#                 print(f'Destination IP: {packet.ipv6.dst}')
#             else:
#                 print('No IP Layer')
#         else:
#             print('No TCP Layer')
#     except AttributeError as e:
#         print(f'Error accessing packet details: {e}')
#     print('---')


# import pyshark

# # Define the filter expression
# filter_expression = 'http2.headers.path contains 208950000000101 or json.value.string == "208950000000101"'

# # Apply the display filter in the FileCapture constructor
# capture = pyshark.FileCapture(_file, display_filter=filter_expression)

# # Process the filtered packets and print the packet number, TCP stream number, frame.time_relative value, src IP, and dest IP
# for packet in capture:
#     print(f'Packet Number: {packet.number}')
#     try:
#         if 'TCP' in packet:
#             print(f'TCP Stream: {packet.tcp.stream}')
#         if hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'time_relative'):
#             print(f'Frame Time Relative: {packet.frame_info.time_relative}')
#         if 'IP' in packet:
#             print(f'Source IP: {packet.ip.src}')
#             print(f'Destination IP: {packet.ip.dst}')
#         elif 'IPv6' in packet:
#             print(f'Source IP: {packet.ipv6.src}')
#             print(f'Destination IP: {packet.ipv6.dst}')
#         else:
#             print('No IP Layer')
#     except AttributeError as e:
#         print(f'Error accessing packet details: {e}')
#     print('---')