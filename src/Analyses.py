
from pprint import pprint
from Constants import *
from PacketsRegister import *
from TIRegister import *

import folium
import matplotlib.pyplot as plt
import plotly.graph_objects as go
#from matplotlib.ticker import MaxNLocator

import random

debug = False

"""
    TODO: Switch to Sankey diagrams?
"""

def display_flows_ips_description_info_graph(file, devname):
    
    ti_reg = TIRegister(file, devname)
    ti_reg.gather_ips_infos()

    src_ips_info = ti_reg.get_ips_infos(ORIGIN_SOURCE_TAG)
    dst_ips_info = ti_reg.get_ips_infos(ORIGIN_DESTINATION_TAG)

    #pprint(src_ips_info)
    #pprint(dst_ips_info)

    src_ips_graph_data, dst_ips_graph_data = ti_reg.get_ips_graph_data_description_per_flows()

    src_names = list(src_ips_graph_data.keys())
    src_values = list(src_ips_graph_data.values())
    #pprint(src_names)


    dst_names = list(dst_ips_graph_data.keys())
    dst_values = list(dst_ips_graph_data.values())
    #pprint(dst_names)

    fig, (ax_src,ax_dst) = plt.subplots(1, 2, figsize=(10,5))
    # TODO: Fix image size to adjust to ticks
    ax_src.barh(src_names, src_values)
    ax_dst.barh(dst_names, dst_values)

    fig.suptitle('IP descriptors SRC and DST flow frequency\n{}'.format(file.split('/')[-1]))
    plt.tight_layout()
    
    for index, value in enumerate(src_values):
        ax_src.text(value, index, str(value), size='x-small')
    for index, value in enumerate(dst_values):
        ax_dst.text(value, index, str(value), size='x-small')

    plt.show()

def display_flows_ports_description_info_graph(file, devname, method='plt'):
    ti_reg = TIRegister(file, devname)
    ti_reg.gather_ports_infos()

    src_ports_info = ti_reg.get_ports_infos(ORIGIN_SOURCE_TAG)
    dst_ports_info = ti_reg.get_ports_infos(ORIGIN_DESTINATION_TAG)

    src_ports_graph_data, dst_ports_graph_data, ports_flows = ti_reg.get_ports_graph_data_service_per_flows()

    if method == 'plt':
        #pprint(src_ports_graph_data)
        #pprint(dst_ports_graph_data)
        
        src_names = list(src_ports_graph_data.keys())
        src_values = list(src_ports_graph_data.values())

        dst_names = list(dst_ports_graph_data.keys())
        dst_values = list(dst_ports_graph_data.values())

        fig, (ax_src, ax_dst) = plt.subplots(1, 2, figsize=(10, 5))
        ax_src.barh(src_names, src_values)
        ax_dst.barh(dst_names, dst_values)

        
        fig.suptitle('Ports services SRC and DST - per flow frequency\n{}'.format(file.split('/')[-1]))
        plt.tight_layout()
    
        for index, value in enumerate(src_values):
            ax_src.text(value, index, str(value), size='x-small')
        for index, value in enumerate(dst_values):
            ax_dst.text(value, index, str(value), size='x-small')

        plt.show()


    elif method == 'sankey':
        #pprint(ports_flows)

        unique_port_labels = list(set().union([el[0] for el in ports_flows] + [el[1] for el in ports_flows]))
        
        print('#############################################')
        pprint(unique_port_labels)

        support_dict = {}
        for el in ports_flows:
            k = str(el[0]) + '~' + str(el[1])
            if k in support_dict.keys():
                support_dict[k][2] += el[2]
            else:
                support_dict[k] = [el[0], el[1], el[2]]

        src = [unique_port_labels.index(flow[0]) for k, flow in support_dict.items()]
        tgt = [unique_port_labels.index(flow[1]) for k, flow in support_dict.items()]
        vals = [flow[2] for k, flow in support_dict.items()]

        #src = [unique_port_labels.index(ports_flow[0]) for ports_flow in ports_flows]
        #tgt = [unique_port_labels.index(ports_flow[1]) for ports_flow in ports_flows]
        #vals = [ports_flow[2] for ports_flow in ports_flows]
        print('#############################################')
        pprint(src)
        pprint(tgt)

        fig = go.Figure(data=go.Sankey(
            node = dict(
                pad = 5,
                thickness = 5,
                line = dict(color = "black", width = 0.5),
                label = unique_port_labels,
                color = "blue"
            ),
            link = dict(
                source = src, # indices correspond to labels, eg A1, A2, A1, B1, ...
                target = tgt,
                value = vals
        )))

        fig.update_layout(title_text="Sankey Diagram of ports", font_size=10)
        fig.show()



"""
def test_things():

    
    ti_reg = TIRegister(file)
    ti_reg.gather_ips_infos(api='geoip')
    ti_reg.gather_ports_infos()

    src_ips_graph_data, dst_ips_graph_data = ti_reg.get_ips_graph_data_description_per_flows()
    src_ports_graph_data, dst_ports_graph_data, comprehensive_ports_graph_data = ti_reg.get_ports_graph_data_service_per_flows()

    src_ips_info = ti_reg.get_ips_infos(ORIGIN_SOURCE_TAG)
    dst_ips_info = ti_reg.get_ips_infos(ORIGIN_DESTINATION_TAG)
    src_ports_info = ti_reg.get_ports_infos(ORIGIN_SOURCE_TAG)
    dst_ports_info = ti_reg.get_ports_infos(ORIGIN_DESTINATION_TAG)

    data = dst_ports_graph_data
    
    names = list(data.keys())
    values = list(data.values())

    print(values)

    #fig, (ax,ax2) = plt.subplots(1, 2, sharey=True)
    fig, ax = plt.subplots()
    ax.barh(names, values)
    #ax2.barh(names, values)

    #ax2.xaxis.set_major_locator(MaxNLocator(integer = True))
    
    #ax.set_xlim(0, values[1] + 5) # most of the data
    #ax2.set_xlim(values[0] - 5, values[0] + 5) # outliers only

    #ax.spines['right'].set_visible(False)
    #ax2.spines['left'].set_visible(False)

    plt.xticks(rotation=45)
    plt.tight_layout()

    plt.show()
"""


def folium_map(file, devname):
    
    output_location = OUTPUTS_FOLDER + devname + '/'
    filename = file.split('/')[-1].split('.')[0]
    outfile = output_location + filename + '.html'

    ti_reg = TIRegister(file, devname)
    ti_reg.gather_ips_infos(api='geoip')

    src_ips_info = ti_reg.get_ips_infos(ORIGIN_SOURCE_TAG)
    dst_ips_info = ti_reg.get_ips_infos(ORIGIN_DESTINATION_TAG)

    pprint(src_ips_info) if debug else None

    m = folium.Map()

    for ip, entry in src_ips_info.items():
        size = str(entry['cntr_flows'])
        label = '<p>Network: ' + entry['desc'] + '\nIP: ' + ip + '\n#Flows: ' + size + '</p>'
        lat = entry['lat_lon'][0] + random.uniform(0, 0.3)
        lon = entry['lat_lon'][1] + random.uniform(0, 0.3)
        colour='green'
        if (entry['desc'] == LOCAL_ADDRESS_TAG):
            colour = 'red'
        folium.Circle(
            radius=200 + int(size) * 10,
            location=[lat, lon],
            color=colour,
            fill_color=colour,
            popup=label
            ).add_to(m)
        #folium.Marker([lat, lon], popup=label, icon=folium.Icon(color=colour)).add_to(m)

    for ip, entry in dst_ips_info.items():
        size = str(entry['cntr_flows'])
        label = '<p>Network: ' + entry['desc'] + '\nIP: ' + ip + '\n#Flows: ' + size + '</p>'
        # Added scattering for visibility
        lat = entry['lat_lon'][0] + random.uniform(0, 0.2)
        lon = entry['lat_lon'][1] + random.uniform(0, 0.2)
        colour='blue',
        if (entry['desc'] == LOCAL_ADDRESS_TAG):
            colour = 'red'
        folium.Circle(
            radius=200 + int(size) * 10,
            location=[lat, lon],
            color=colour,
            fill_color=colour,
            popup=label
            ).add_to(m)

        #folium.Marker([lat, lon], popup=label, icon=folium.Icon(color=colour)).add_to(m)
    
    m.save(outfile)
    print('>>> Map of source and destination IPs saved to: {}'.format(outfile))



if __name__ == '__main__':

    #file = OUTPUTS_FOLDER + 'ieee-ezviz-complete/scan-portos-all-ezviz-rejected.json'
    #file = OUTPUTS_FOLDER + 'ieee-ezviz-complete/mirai-httpflooding-all-ezviz-rejected.pcap'
    #file = OUTPUTS_FOLDER + 'ieee-ezviz-complete/mirai-ackflooding-all-ezviz-rejected.json'
    file = OUTPUTS_FOLDER + 'ieee-ezviz-complete/mirai-httpflooding-all-ezviz-rejected.json'
    
    #display_flows_ips_description_info_graph(file)

    display_flows_ports_description_info_graph(file)

    #folium_tests('a')
    
