from django.shortcuts import render
import pyshark
from .models import ModelWithFileField
import sumpractice.settings
import os
import PacketReader


def index(request):
    return render(request, 'index.html')


def upload(request):
    global mac_dst_src_list
    ModelWithFileField.objects.all().delete()
    conversations = []
    conv_pull = []
    conv_count = []
    conv_pull_to_exit = []
    tcp_ip_pull = []
    ipv4_ip_pull = []
    try:
        print('1')
        if request.method == 'POST':
            # Проверка на расширение .pcap!
            # form = forms.UploadFileForm(request.POST, request.FILES)
            upload_file = request.FILES['document']
            instance = ModelWithFileField(name=upload_file.name, file_field=request.FILES['document'])
            instance.save()
            print(upload_file.name)
            capture = pyshark.FileCapture(os.path.join(sumpractice.settings.MEDIA_ROOT, str(upload_file)))
            mac_dst_src_list = mac_addresses(os.path.join(sumpractice.settings.MEDIA_ROOT, str(upload_file)))
            for packet in capture:
                results = network_conversation(packet)
                resultat = network_conversation_inverse(packet)
                if results is not None:
                    conversations.append(results)
                if resultat in conv_pull:
                    indx = conv_pull.index(resultat)
                    conv_count[indx] = conv_count[indx] + 1
                else:
                    conv_pull.append(resultat)
                    conv_pull_to_exit.append(results)
                    conv_count.append(1)
                if tcp_source_info(packet) in tcp_ip_pull:
                    pass
                else:
                    tcp_ip_pull.append(tcp_source_info(packet))
                if tcp_destination_info(packet) in tcp_ip_pull:
                    pass
                else:
                    tcp_ip_pull.append(tcp_destination_info(packet))
                if ipv4_source_info(packet) in ipv4_ip_pull:
                    pass
                else:
                    ipv4_ip_pull.append(ipv4_source_info(packet))
                if ipv4_destination_info(packet) in ipv4_ip_pull:
                    pass
                else:
                    ipv4_ip_pull.append(ipv4_destination_info(packet))
            capture.close()
        else:
            return render(request, 'newupload.html')
    except Exception as e:
        print('Problem with upload. In views.py ' + str(e))
        pass

    sum_of_packets = 0
    for _sum_of_packet in conv_count:
        sum_of_packets = sum_of_packets + _sum_of_packet

    conv = union_array(conv_pull_to_exit, conv_count)
    return render(request, 'newresults.html', context={'conversations': conversations,
                                                       'conversation_pull': conv_pull,
                                                       'repeat_counter': conv,
                                                       'tcp_ip_pull': sorted(tcp_ip_pull),
                                                       'ipv4_ip_pull': sorted(ipv4_ip_pull),
                                                       'mac_addresses': mac_dst_src_list,
                                                       'all_packets': sum_of_packets})


def network_conversation(_packet):
    try:
        protocol = _packet.transport_layer
        source_address = _packet.ip.src
        source_port = _packet[_packet.transport_layer].srcport
        destination_address = _packet.ip.dst
        destination_port = _packet[_packet.transport_layer].dstport
        return f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}'
    # :f'{protocol} {destination_address}:{destination_port} --> {source_address}:{source_port}'}
    except AttributeError as e:
        return e


def network_conversation_inverse(_packet):
    try:
        protocol = _packet.transport_layer
        source_address = _packet.ip.src
        source_port = _packet[_packet.transport_layer].srcport
        destination_address = _packet.ip.dst
        destination_port = _packet[_packet.transport_layer].dstport
        return sorted([f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}',
                       f'{protocol} {destination_address}:{destination_port} --> {source_address}:{source_port}'])
    except AttributeError as e:
        return e


def tcp_source_info(_packet):
    source_address = _packet.ip.src
    source_port = _packet[_packet.transport_layer].srcport
    return f'{source_address}:{source_port}'


def tcp_destination_info(_packet):
    destination_address = _packet.ip.dst
    destination_port = _packet[_packet.transport_layer].dstport
    return f'{destination_address}:{destination_port}'


def ipv4_source_info(_packet):
    source_address = _packet.ip.src
    return f'{source_address}'


def ipv4_destination_info(_packet):
    destination_address = _packet.ip.dst
    return f'{destination_address}'


def mac_addresses(_upload_file):
    mcadr = []
    packets = PacketReader.read_pcap(os.path.join(sumpractice.settings.MEDIA_ROOT, str(_upload_file)))
    for packet in packets:
        _madrsrc = packet.mac_address(packet.ethernet_header['SRC'])
        if _madrsrc in mcadr:
            pass
        else:
            mcadr.append(_madrsrc)
        _madrdst = packet.mac_address(packet.ethernet_header['DST'])
        if _madrdst in mcadr:
            pass
        else:
            mcadr.append(_madrdst)
    return mcadr


def union_array(_a, _b):
    c = []
    if _a.__len__() != _b.__len__():
        print(str(_a.__len__()) + ' != ' + str(_b.__len__()))
        print("Error in union array!")
    else:
        for i in range(_a.__len__()):
            _c = f'{_a[i]} .........> {_b[i]}times'
            c.append(_c)
    return c
