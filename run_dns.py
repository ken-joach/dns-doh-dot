###################################################################################################
#
# Author: Kendra Joachim
# Name: Testing Latency and Response Size of Standard DNS, DNS over HTTPS, and DNS over TLS
# Date: December 12, 2025
# References:
#   - Testing is based on https://www.youtube.com/watch?v=W7wymOhQlSc
#   - Reference for dns.resolver: https://dnspython.readthedocs.io/en/latest/resolver-class.html
#   - Reference for httpx: https://www.python-httpx.org/quickstart/
#   - Reference for OpenSSL's s_client: https://docs.openssl.org/1.0.2/man1/s_client/
#
###################################################################################################

import csv
import datetime
import dns.resolver
import httpx
import matplotlib.pyplot as plt
import subprocess # needed to do DoT with openssl
import time

# configuration
QUERY_NAME = "example.com"
QUERY_LIST = {
    "google.com", "wikipedia.org", "cloudflare.com", "amazon.com", "apple.com",
    "europa.eu", "gov.uk", "ebay.com", "tu-berlin.de", "spotify.com",
    "microsoft.com", "netflix.com", "wikipedia.org", "mozilla.org", "github.com",
    "stackoverflow.com", "reddit.com", "nytimes.com", "cnn.com", "bbc.co.uk",
    "mit.edu", "quora.com", "yahoo.com", "harvard.edu", "imgur.com",
    "ox.ac.uk", "nhk.or.jp", "theguardian.com", "naver.com", "cbc.ca"
    "cam.ac.uk", "utoronto.ca", "oracle.com", "edf.fr", "sony.jp",
    "kakao.com", "abc.net.au", "auckland.ac.nz", "espn.com", "cisco.com",
    "openai.com", "twitch.tv", "ubuntu.com", "zoom.us", "salesforce.com",
    "python.org", "dropbox.com", "kubernetes.io", "nodejs.org", "golang.org"
}
NUM_TRIALS = 50 # number of tests for each type

# Set resolvers and endpoints
# cloudflare documentation: https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/
# google documentation:     https://developers.google.com/speed/public-dns/docs/doh
RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8"
}

DOH_ENDPOINTS = {
    "cloudflare" : {
        "url": "https://1.1.1.1/dns-query",
        "host": "cloudflare-dns.com"
    },
    "google": {
        "url": "https://8.8.8.8/resolve",
        "host": "dns.google"
    }
}

CSV_FILE = "dns_doh_dot.csv"

NETWORK_RTT_MS = 0
LOSS_PCT = 0

# csv initialization
def init_csv():
    with open(CSV_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "timestamp", "protocol", "resolver", "warm_or_cold", "trial", "query_name", "latency", "response_bytes", "success", "notes"
        ])

def log_row(data):
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(data)

def now():
    return datetime.datetime.now().astimezone()

# standard DNS over UDP
def run_dns_udp_tests(resolver_name, resolver_ip, logs, avgs_lat, avgs_rb):
    print(f"----- RUNNING DNS OVER UDP ({resolver_name})-----")

    # set up the resolver with the desired nameserver
    resolver_cold = dns.resolver.Resolver()
    resolver_cold.nameservers = [resolver_ip]
    resolver_cold.cache = None # no cache to simulate having to do full query each time

    # run cold
    run_dns_udp(resolver_cold, logs, avgs_lat, avgs_rb, resolver_name, run_cold=True)

    resolver_warm = dns.resolver.Resolver()
    resolver_warm.nameservers = [resolver_ip]
    # run warm
    run_dns_udp(resolver_warm, logs, avgs_lat, avgs_rb, resolver_name, run_cold=False)

def run_dns_udp(resolver, logs, avgs_lat, avgs_rb, resolver_name, run_cold):
    if run_cold:
        print("Running cold")
    else:
        print("Running warm")
    sum_latency = 0
    sum_rb = 0
    for i in range(NUM_TRIALS):
        try:
            # run query
            start = time.perf_counter()
            answer = resolver.resolve(QUERY_NAME, "A")
            end = time.perf_counter()

            # get measurements
            latency = (end - start) * 1000 # in miliseconds
            resp_bytes = len(answer.response.to_wire())
            success = True
            notes = ""
        # note exceptions if they occur
        except Exception as e:
            latency = 0
            resp_bytes = 0
            success = False
            notes = str(e)
        sum_latency += latency
        sum_rb += resp_bytes
        if run_cold:
            if resolver_name == "cloudflare":
                logs['cold_cloud'].append(latency)
            else:
                logs['cold_google'].append(latency)
            log_row([now(), "UDP", resolver_name, "cold", i, QUERY_NAME, latency, resp_bytes, success, notes])
        else:
            if resolver_name == "cloudflare":
                logs['warm_cloud'].append(latency)
            else:
                logs['warm_google'].append(latency)
            log_row([now(), "UDP", resolver_name, "warm", i, QUERY_NAME, latency, resp_bytes, success, notes])
    # log averages
    avg_latency = sum_latency/NUM_TRIALS
    avg_rb = sum_rb/NUM_TRIALS
    avgs_lat.append(avg_latency)
    avgs_rb.append(avg_rb)

# DNS over HTTPS (DoH)
def run_doh(resolver_name, logs, avgs_lat, avgs_rb):
    print(f"----- RUNNING DNS OVER HTTPS ({resolver_name}) -----")

    url = DOH_ENDPOINTS[resolver_name]["url"]
    params = {"name": QUERY_NAME, "type": "A"}
    headers = {"accept": "application/dns-json"}

    # run cold
    run_doh_cold(resolver_name, avgs_lat, avgs_rb, url, params, headers, logs)
    # run warm
    run_doh_warm(resolver_name, avgs_lat, avgs_rb, url, params, headers, logs)

def run_doh_warm(resolver_name, avgs_lat, avgs_rb, url, params, headers, logs):
    print("Running warm")
    client = httpx.Client(timeout=5.0)
    sum_lat = 0
    sum_rb = 0
    for i in range(NUM_TRIALS):
        try:
            # run query
            start = time.perf_counter()
            response = client.get(url, params=params, headers=headers)
            end = time.perf_counter()

            # get measurements
            latency = (end - start) * 1000 # in miliseconds
            resp_bytes = len(response.content)
            success = (response.status_code == 200)  # 200 = OK
            notes = f"status={response.status_code}" # 400 = Bad Request
        # note exceptions if they occur
        except Exception as e:
            latency = 0
            resp_bytes = 0
            success = False
            notes = str(e)
        
        # logging
        sum_lat += latency
        sum_rb += resp_bytes
        if resolver_name == "cloudflare":
            logs['warm_cloud'].append(latency)
        else:
            logs['warm_google'].append(latency)
        log_row([now(), "DoH", resolver_name, "warm", i, QUERY_NAME, latency, resp_bytes, success, notes])

    client.close()
    avg_lat = sum_lat/NUM_TRIALS
    avg_rb = sum_rb/NUM_TRIALS
    avgs_lat.append(avg_lat)
    avgs_rb.append(avg_rb)

def run_doh_cold(resolver_name, avgs_lat, avgs_rb,  url, params, headers, logs):
    print("Running cold")
    sum_lat = 0
    sum_rb = 0
    for i in range(NUM_TRIALS):
        try:
            # run query
            start = time.perf_counter()
            response = httpx.get(url, params=params,headers=headers, timeout=5.0)
            end = time.perf_counter()

            # get measurements
            latency = (end - start) * 1000 # in miliseconds
            resp_bytes = len(response.content)
            success = (response.status_code == 200)  # 200 = OK
            notes = f"status={response.status_code}" # 400 = Bad Request
        # note exceptions if they occur
        except Exception as e:
            latency = 0
            resp_bytes = 0
            success = False
            notes = str(e)
        
        # logging
        sum_lat += latency
        sum_rb += resp_bytes
        if resolver_name == "cloudflare":
            logs['cold_cloud'].append(latency)
        else:
            logs['cold_google'].append(latency)
        log_row([now(), "DoH", resolver_name, "cold", i, QUERY_NAME, latency, resp_bytes, success, notes])
    avg_lat = sum_lat/NUM_TRIALS
    avg_rb = sum_rb/NUM_TRIALS
    avgs_lat.append(avg_lat)
    avgs_rb.append(avg_rb)

# DNS over TLS (DoT)
def run_dot(resolver_name, resolver_ip, logs, avgs_lat):
    print(f"----- RUNNING DNS OVER TLS ({resolver_name}) -----")

    cmd = [
        "openssl", "s_client",
        "-connect", f"{resolver_ip}:853",
        "-servername", DOH_ENDPOINTS[resolver_name]["host"]
    ]
    sum = 0
    for i in range(NUM_TRIALS):
        try:
            # run query
            start = time.perf_counter()
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, input=b"\n", timeout=10)
            end = time.perf_counter()

            # get measurements
            latency = (end - start) * 1000 # in miliseconds
            success = True
            notes = ""
        # note exceptions if they occur
        except Exception as e:
            latency = 0
            success = False
            notes = str(e)
        
        sum += latency
        if resolver_name == "cloudflare":
            logs['cloud'].append(latency)
        else:
            logs['google'].append(latency)
        log_row([now(), "DoT", resolver_name, "n/a", i, QUERY_NAME, latency, "", success, notes])

    avgs_lat.append(sum/NUM_TRIALS)

def main():
    # create logs
    udp_logs = {
        'cold_cloud': [],
        'warm_cloud': [],
        'cold_google': [],
        'warm_google': []
    }

    doh_logs = {
        'cold_cloud': [],
        'warm_cloud': [],
        'cold_google': [],
        'warm_google': []
    }

    dot_logs = {
        'cloud': [],
        'google': []
    }

    # logs for averages
    avgs_lat = []
    avgs_rb = []
    avg_names = ["DNS Cold Cloudflare", "DNS Warm Cloudflare", "DNS Cold Google", "DNS Warm Google",
                 "DoH Cold Cloudflare", "DoH Warm Cloudflare", "DoH Cold Google", "DoH Warm Google",
                 "DoT Cloudflare", "DoT Google"]
    combo_avgs_lat = []
    combo_avg_names = ["DNS Cold", "DNS Warm", "DoH Cold", "DoH Warm", "DoT"]
    combo_avgs_rb = []
    combo_avg_names_rb = ["DNS", "DoH"]

    # get number of trials for x-axis of line plots
    trials = []
    for i in range(NUM_TRIALS):
        trials.append(i + 1)

    # initialize the csv file
    init_csv()

    # run tests on each revolver and each DNS type
    for name, ip in RESOLVERS.items():
        run_dns_udp_tests(name, ip, udp_logs, avgs_lat, avgs_rb)
    for name, _ in RESOLVERS.items():
        run_doh(name, doh_logs, avgs_lat, avgs_rb)
    for name, ip in RESOLVERS.items():
        run_dot(name, ip, dot_logs, avgs_lat)
    print(f"Done running. Results saved to {CSV_FILE}. Plotting graphs...")

    # combine the averages of tests with negligible differences
    combo_avgs_lat.append((avgs_lat[0] + avgs_lat[2])/2) # DNS Cold
    combo_avgs_lat.append((avgs_lat[1] + avgs_lat[3])/2) # DNS Warm
    combo_avgs_lat.append((avgs_lat[4] + avgs_lat[6])/2) # DoH Cold
    combo_avgs_lat.append((avgs_lat[5] + avgs_lat[7])/2) # DoH Warm
    combo_avgs_lat.append((avgs_lat[8] + avgs_lat[9])/2) # DoT

    combo_avgs_rb.append((avgs_rb[0] + avgs_rb[1] + avgs_rb[2] + avgs_rb[3])/4) # All DNS
    combo_avgs_rb.append((avgs_rb[4] + avgs_rb[5] + avgs_rb[6] + avgs_rb[7])/4) # All DoH

    # print first values and averages
    print("----- Latency Averages -----")
    print(f"DNS Cold Average: {combo_avgs_lat[0]:.2f} ms")
    print(f"DNS Warm Average: {combo_avgs_lat[1]:.2f} ms")
    print(f"DoH Cold Average: {combo_avgs_lat[2]:.2f} ms")
    print(f"DoH Warm Average: {combo_avgs_lat[3]:.2f} ms")
    print(f"DoT Average:      {combo_avgs_lat[4]:.2f} ms")
    print("----- Average Number of Response Bytes -----")
    print(f"DNS: {combo_avgs_rb[0]:.1f} bytes")
    print(f"DoH: {combo_avgs_rb[1]:.1f} bytes")

    # plotting
    fig1 = plt.figure(figsize=(8,6))
    fig2 = plt.figure(figsize=(8,6))
    fig3 = plt.figure(figsize=(8,6))
    fig4 = plt.figure(figsize=(8,6))
    fig5 = plt.figure(figsize=(8,6))
    fig6 = plt.figure(figsize=(8,6))
    fig7 = plt.figure(figsize=(8,6))
    fig8 = plt.figure(figsize=(8,6))

    udp_plot = fig1.add_subplot(111)
    udp_plot.plot(trials, udp_logs["cold_cloud"], label='Cold with Cloudflare')
    udp_plot.plot(trials, udp_logs["cold_google"], label='Cold with Google')
    udp_plot.plot(trials, udp_logs["warm_cloud"], label='Warm with Cloudflare')
    udp_plot.plot(trials, udp_logs["warm_google"], label='Warm with Google')
    udp_plot.set_xlabel("Trial Number")
    udp_plot.set_ylabel("Latency (ms)")
    udp_plot.set_title("Standard DNS")
    udp_plot.legend()

    doh_plot = fig2.add_subplot(111)
    doh_plot.plot(trials, doh_logs["cold_cloud"], label='Cold with Cloudflare')
    doh_plot.plot(trials, doh_logs["cold_google"], label='Cold with Google')
    doh_plot.plot(trials, doh_logs["warm_cloud"], label='Warm with Cloudflare')
    doh_plot.plot(trials, doh_logs["warm_google"], label='Warm with Google')
    doh_plot.set_xlabel("Trial Number")
    doh_plot.set_ylabel("Latency (ms)")
    doh_plot.set_title("DNS over HTTPS (DoH)")
    doh_plot.legend()

    dot_plot = fig3.add_subplot(111)
    dot_plot.plot(trials, dot_logs["cloud"], label='DoT with Cloudflare')
    dot_plot.plot(trials, dot_logs["google"], label='DoT with Google')
    dot_plot.set_xlabel("Trial Number")
    dot_plot.set_ylabel("Latency (ms)")
    dot_plot.set_title("DNS over TLS (DoT)")
    dot_plot.legend()

    all_three = fig4.add_subplot(111)
    all_three.plot(trials, udp_logs["cold_cloud"], label='DNS Cold with Cloudflare')
    all_three.plot(trials, udp_logs["cold_google"], label='DNS Cold with Google')
    all_three.plot(trials, udp_logs["warm_cloud"], label='DNS Warm with Cloudflare')
    all_three.plot(trials, udp_logs["warm_google"], label='DNS Warm with Google')
    all_three.plot(trials, doh_logs["cold_cloud"], label='DOH Cold with Cloudflare')
    all_three.plot(trials, doh_logs["cold_google"], label='DOH Cold with Google')
    all_three.plot(trials, doh_logs["warm_cloud"], label='DOH Warm with Cloudflare')
    all_three.plot(trials, doh_logs["warm_google"], label='DOH Warm with Google')
    all_three.plot(trials, dot_logs["cloud"], label='DoT with Cloudflare')
    all_three.plot(trials, dot_logs["google"], label='DoT with Google')
    all_three.set_xlabel("Trial Number")
    all_three.set_ylabel("Latency (ms)")
    all_three.set_title("Standard DNS v. DNS over HTTPS (DoH)")
    all_three.legend()

    avgs_lat_bar = fig5.add_subplot(111)
    avgs_lat_bar.bar(avg_names, avgs_lat)
    avgs_lat_bar.set_ylabel("Latency (ms)")
    avgs_lat_bar.set_title(f"Average Latencies(ms) for {NUM_TRIALS} Trials")

    combo_avgs_lat_bar = fig6.add_subplot(111)
    combo_avgs_lat_bar.bar(combo_avg_names, combo_avgs_lat)
    combo_avgs_lat_bar.set_ylabel("Latency (ms)")
    combo_avgs_lat_bar.set_title(f"Average Latencies(ms) for {NUM_TRIALS*2} Trials")

    avgs_rb_bar = fig7.add_subplot(111)
    avgs_rb_bar.bar(avg_names[:8], avgs_rb)
    avgs_rb_bar.set_ylabel("Number of Bytes in Response")
    avgs_rb_bar.set_title(f"Average Number of Response Bytes for {NUM_TRIALS} Trials")

    combo_avgs_rb_bar = fig8.add_subplot(111)
    combo_avgs_rb_bar.bar(combo_avg_names_rb, combo_avgs_rb)
    combo_avgs_rb_bar.set_ylabel("Number of Bytes in Response")
    combo_avgs_rb_bar.set_title(f"Average Number of Response Bytes for {NUM_TRIALS*4} Trials")

    plt.show()

if __name__ == "__main__":
    main()
