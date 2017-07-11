from flask import Flask, request, redirect, url_for, render_template, current_app
from pygal import XY, Bar
import filter_static
import filter_dynamic
import sys
import json

app = Flask(__name__)

@app.route('/static', methods=['GET', 'POST'])
def static_pcap():
    if request.method == 'POST':
        #temporarily store upload pcap file
        print request
        traceFile = request.files['file']
        traceFile.save("temporary/temp_pcap_file.pcap")

        ft = filter_static.Static_Filter(fileName ="temporary/temp_pcap_file.pcap")
        device_traffic_dict = ft.detect_Device()

        #line chart for individual device data sent historys
        pkt_line = XY(width=800, height=600, explicit_size=True)
        pkt_line.title = 'Device Package Curve'
        for key, list in device_traffic_dict.iteritems():
            pkt_line.add(key, list)
        chart = pkt_line.render()

        # bar chart for device data sent summary
        pkt_Bar = Bar(width=800, height=600, explicit_size=True)
        pkt_Bar.title = 'Device Package Sum'
        for key, list in device_traffic_dict.iteritems():
            zipped = map(sum, zip(*list))
            pkt_Bar.add(key, zipped[1])
        pkt_Bar = pkt_Bar.render()

        del ft
        html = """{} {}""".format(chart, pkt_Bar)
        return html

    else:
        return current_app.send_static_file('static.html')

@app.route('/dynamic', methods=['GET', 'POST'])
def dynamic_pcap():
    if request.method == 'POST':
        #temporarily store upload pcap file
        time = int(request.form['time'])

        ft = filter_dynamic.Dynamic_Filter(time=time)
        try:
            data_lists = ft.live_Capture() #[ARP_Collection, APR_Package, IP_Collection, IP_Package]
        except:
            sys.exit("no package detected")

        ARP_Collection = data_lists[0]
        APR_Package = data_lists[1]
        IP_Collection = data_lists[2]
        IP_Package = data_lists[3]

        #line chart for ARP DELTA Information
        pkt_line_ARP = XY(width=800, height=600, explicit_size=True)
        pkt_line_ARP.title = 'Time delta for ARP'
        for key, list in ARP_Collection.iteritems():
            pkt_line_ARP.add(key, list)
        chart_ARP_Delta = pkt_line_ARP.render()

        # line chart for ARP Package Information
        pkt_line_ARP = XY(width=800, height=600, explicit_size=True)
        pkt_line_ARP.title = 'Package Info for ARP'
        for key, list in APR_Package.iteritems():
            pkt_line_ARP.add(key, list)
        chart_ARP_Package = pkt_line_ARP.render()

        pkt_line_IP = XY(width=800, height=600, explicit_size=True)
        pkt_line_IP.title = 'Time delta for IP'
        for key, list in IP_Collection.iteritems():
            pkt_line_IP.add(key, list)
        chart_IP_Delta = pkt_line_IP.render()

        pkt_line_IP = XY(width=800, height=600, explicit_size=True)
        pkt_line_IP.title = 'Package Info for IP'
        for key, list in IP_Package.iteritems():
            pkt_line_IP.add(key, list)
        chart_IP_Package = pkt_line_IP.render()

        del ft
        html = """{} {} <br/> {} {}""".format(chart_ARP_Package, chart_ARP_Delta, chart_IP_Package, chart_IP_Delta)
        return html

    else:
        return current_app.send_static_file('dynamic.html')

@app.route('/captured_dynamic', methods=['GET', 'POST'])
def captured_dynamic_pcap():
    if request.method == 'POST':
        traceFile = request.files['file']
        data_lists = json.load(traceFile)

        ARP_Collection = data_lists[0]
        APR_Package = data_lists[1]
        IP_Collection = data_lists[2]
        IP_Package = data_lists[3]

        # line chart for ARP DELTA Information
        pkt_line_ARP = XY(width=800, height=600, explicit_size=True)
        pkt_line_ARP.title = 'Time delta for ARP'
        for key, list in ARP_Collection.iteritems():
            pkt_line_ARP.add(key, list)
        chart_ARP_Delta = pkt_line_ARP.render()

        # line chart for ARP Package Information
        pkt_line_ARP = XY(width=800, height=600, explicit_size=True)
        pkt_line_ARP.title = 'Package Info for ARP'
        for key, list in APR_Package.iteritems():
            pkt_line_ARP.add(key, list)
        chart_ARP_Package = pkt_line_ARP.render()

        pkt_line_IP = XY(width=800, height=600, explicit_size=True)
        pkt_line_IP.title = 'Time delta for IP'
        for key, list in IP_Collection.iteritems():
            pkt_line_IP.add(key, list)
        chart_IP_Delta = pkt_line_IP.render()

        pkt_line_IP = XY(width=800, height=600, explicit_size=True)
        pkt_line_IP.title = 'Package Info for IP'
        for key, list in IP_Package.iteritems():
            pkt_line_IP.add(key, list)
        chart_IP_Package = pkt_line_IP.render()

        html = """{} {} <br/> {} {}""".format(chart_ARP_Package, chart_ARP_Delta, chart_IP_Package, chart_IP_Delta)
        return html

    else:
        return current_app.send_static_file('captured_dynamic.html')

if __name__ == '__main__':
    app.run(debug=True)