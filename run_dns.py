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
    "ox.ac.uk", "bing.com", "theguardian.com", "naver.com", "youtube.com",
    "cam.ac.uk", "utoronto.ca", "oracle.com", "edf.fr", "sony.jp", 
    "kakao.com", "abc.net.au", "auckland.ac.nz", "espn.com", "cisco.com",
    "openai.com", "twitch.tv", "ubuntu.com", "zoom.us", "salesforce.com",
    "python.org", "dropbox.com", "kubernetes.io", "nodejs.org", "golang.org", "instagram.com"
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

    resolver_rw = dns.resolver.Resolver()
    resolver_rw.nameservers = [resolver_ip]
    # run real world
    run_dns_udp_rw(resolver_rw, logs, avgs_lat, avgs_rb, resolver_name)

def run_dns_udp(resolver, logs, avgs_lat, avgs_rb, resolver_name, run_cold):
    if run_cold:
        print("Running cold...")
    else:
        print("Running warm...")
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

def run_dns_udp_rw(resolver, logs, avgs_lat, avgs_rb, resolver_name):
    print("Running real world...")
    sum_lat = 0
    sum_rb = 0
    i = 0
    for query_name in QUERY_LIST:
        try:
            start = time.perf_counter()
            answer = resolver.resolve(query_name, "A")
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
        sum_lat += latency
        sum_rb += resp_bytes
        if resolver_name == "cloudflare":
            logs['rw_cloud'].append(latency)
        else:
            logs['rw_google'].append(latency)
        log_row([now(), "UDP", resolver_name, "rw", i, query_name, latency, resp_bytes, success, notes])
        i += 1
    avg_lat = sum_lat/NUM_TRIALS
    avg_rb = sum_rb/NUM_TRIALS
    avgs_lat.append(avg_lat)
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
    run_doh_warm(resolver_name, avgs_lat, avgs_rb, url, headers, logs)
    # run real world
    run_doh_realworld(resolver_name, avgs_lat, avgs_rb, url, headers, logs)

def run_doh_warm(resolver_name, avgs_lat, avgs_rb, url, headers, logs):
    print("Running warm...")
    client = httpx.Client(timeout=5.0)
    sum_lat = 0
    sum_rb = 0
    for i in range(NUM_TRIALS):
        try:
            params = {"name": QUERY_NAME, "type": "A"}
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

def run_doh_cold(resolver_name, avgs_lat, avgs_rb, url, params, headers, logs):
    print("Running cold...")
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

def run_doh_realworld(resolver_name, avgs_lat, avgs_rb, url, headers, logs):
    print("Running real world...")
    client = httpx.Client(timeout=5.0)
    sum_lat = 0
    sum_rb = 0
    i = 0
    for query_name in QUERY_LIST:
        try:
            params = {"name": query_name, "type": "A"}
            # run query
            start = time.perf_counter()
            response = client.get(url, params=params, headers=headers)
            end = time.perf_counter()

            # get measurements
            latency = (end - start) * 1000 # in miliseconds
            resp_bytes = len(response.content)
            success = (response.status_code == 200)  # 200 = OK
            notes = f"status={response.status_code}" # 400 = Bad Request
        except Exception as e:
            latency = 0
            resp_bytes = 0
            success = False
            notes = str(e)
        i += 1
        sum_lat += latency
        sum_rb += resp_bytes
        if resolver_name == "cloudflare":
            logs['rw_cloud'].append(latency)
        else:
            logs['rw_google'].append(latency)
        log_row([now(), "DoH", resolver_name, "rw", i, query_name, latency, resp_bytes, success, notes])
    client.close()
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
        'rw_cloud': [],
        'cold_google': [],
        'warm_google': [],
        'rw_google': []
    }

    doh_logs = {
        'cold_cloud': [],
        'warm_cloud': [],
        'rw_cloud': [],
        'cold_google': [],
        'warm_google': [],
        'rw_google': []
    }

    dot_logs = {
        'cloud': [],
        'google': []
    }

    # logs for averages
    avgs_lat = []
    avgs_rb = []
    avg_names = ["DNS Cold Cloud", "DNS Warm Cloud", "DNS RW Cloud",
                 "DNS Cold Google", "DNS Warm Google", "DNS RW Google",
                 "DoH Cold Cloud", "DoH Warm Cloud", "DoH RW Cloud",
                 "DoH Cold Google", "DoH Warm Google", "DoH RW Google",
                 "DoT Cloud", "DoT Google"]
    combo_avgs_lat = []
    combo_avg_names = ["DNS Cold", "DNS Warm", "DNS RW", "DoH Cold", "DoH Warm", "DoH RW", "DoT"]
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
    combo_avgs_lat.append((avgs_lat[0] + avgs_lat[3])/2) # DNS Cold
    combo_avgs_lat.append((avgs_lat[1] + avgs_lat[4])/2) # DNS Warm
    combo_avgs_lat.append((avgs_lat[2] + avgs_lat[5])/2) # DNS Real World
    combo_avgs_lat.append((avgs_lat[6] + avgs_lat[9])/2) # DoH Cold
    combo_avgs_lat.append((avgs_lat[7] + avgs_lat[10])/2) # DoH Warm
    combo_avgs_lat.append((avgs_lat[8] + avgs_lat[11])/2) # DoH Real World
    combo_avgs_lat.append((avgs_lat[12] + avgs_lat[13])/2) # DoT

    combo_avgs_rb.append((avgs_rb[0] + avgs_rb[1] + avgs_rb[2] + avgs_rb[3] + avgs_rb[4] + avgs_rb[5])/6) # All DNS
    combo_avgs_rb.append((avgs_rb[6] + avgs_rb[7] + avgs_rb[8] + avgs_rb[9] + avgs_rb[10] + avgs_rb[11])/6) # All DoH

    # print first values and averages
    print("----- Latency Averages -----")
    print(f"DNS Cold Average:         {combo_avgs_lat[0]:.2f} ms")
    print(f"DNS Warm Average:         {combo_avgs_lat[1]:.2f} ms")
    print(f"DNS \"Real World\" Average: {combo_avgs_lat[2]:.2f} ms")
    print(f"DoH Cold Average:         {combo_avgs_lat[3]:.2f} ms")
    print(f"DoH Warm Average:         {combo_avgs_lat[4]:.2f} ms")
    print(f"DoH \"Real World\" Average: {combo_avgs_lat[5]:.2f} ms")
    print(f"DoT Average:              {combo_avgs_lat[6]:.2f} ms")
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
    fig9 = plt.figure(figsize=(8,6))

    udp_plot = fig1.add_subplot(111)
    udp_plot.plot(trials, udp_logs["cold_cloud"], label='Cold with Cloudflare')
    udp_plot.plot(trials, udp_logs["cold_google"], label='Cold with Google')
    udp_plot.plot(trials, udp_logs["warm_cloud"], label='Warm with Cloudflare')
    udp_plot.plot(trials, udp_logs["warm_google"], label='Warm with Google')
    udp_plot.plot(trials, udp_logs["rw_cloud"], label='RW with Cloudflare')
    udp_plot.plot(trials, udp_logs["rw_google"], label='RW with Google')
    udp_plot.set_xlabel("Trial Number")
    udp_plot.set_ylabel("Latency (ms)")
    udp_plot.set_title("Standard DNS")
    udp_plot.legend()

    doh_plot = fig2.add_subplot(111)
    doh_plot.plot(trials, doh_logs["cold_cloud"], label='Cold with Cloudflare')
    doh_plot.plot(trials, doh_logs["cold_google"], label='Cold with Google')
    doh_plot.plot(trials, doh_logs["warm_cloud"], label='Warm with Cloudflare')
    doh_plot.plot(trials, doh_logs["warm_google"], label='Warm with Google')
    doh_plot.plot(trials, doh_logs["rw_cloud"], label='RW with Cloudflare')
    doh_plot.plot(trials, doh_logs["rw_google"], label='RW with Google')
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

    all_three_c = fig4.add_subplot(111)
    all_three_c.plot(trials, udp_logs["cold_cloud"], label='DNS Cold with Cloudflare')
    all_three_c.plot(trials, udp_logs["warm_cloud"], label='DNS Warm with Cloudflare')
    all_three_c.plot(trials, udp_logs["rw_cloud"], label='DNS RW with Cloudflare')
    all_three_c.plot(trials, doh_logs["cold_cloud"], label='DoH Cold with Cloudflare')
    all_three_c.plot(trials, doh_logs["warm_cloud"], label='DoH Warm with Cloudflare')
    all_three_c.plot(trials, doh_logs["rw_cloud"], label='DoH RW with Cloudflare')
    all_three_c.plot(trials, dot_logs["cloud"], label='DoT with Cloudflare')
    all_three_c.set_xlabel("Trial Number")
    all_three_c.set_ylabel("Latency (ms)")
    all_three_c.set_title("Standard DNS v. DNS over HTTPS (DoH) v. DNS over TLS (DoT)")
    all_three_c.legend()

    all_three_g = fig5.add_subplot(111)
    all_three_g.plot(trials, udp_logs["cold_google"], label='DNS Cold with Google')
    all_three_g.plot(trials, udp_logs["warm_google"], label='DNS Warm with Google')
    all_three_g.plot(trials, udp_logs["rw_google"], label='DNS RW with Google')
    all_three_g.plot(trials, doh_logs["cold_google"], label='DoH Cold with Google')
    all_three_g.plot(trials, doh_logs["warm_google"], label='DoH Warm with Google')
    all_three_g.plot(trials, doh_logs["rw_google"], label='DoH RW with Google')
    all_three_g.plot(trials, dot_logs["google"], label='DoT with Google')
    all_three_g.set_xlabel("Trial Number")
    all_three_g.set_ylabel("Latency (ms)")
    all_three_g.set_title("Standard DNS v. DNS over HTTPS (DoH) v. DNS over TLS (DoT)")
    all_three_g.legend()

    avgs_lat_bar = fig6.add_subplot(111)
    bars1 = avgs_lat_bar.bar(avg_names, avgs_lat)
    avgs_lat_bar.bar_label(bars1, fmt="%.2f ms")
    avgs_lat_bar.set_ylabel("Latency (ms)")
    avgs_lat_bar.set_title(f"Average Latencies(ms) for {NUM_TRIALS} Trials")

    combo_avgs_lat_bar = fig7.add_subplot(111)
    bars2 = combo_avgs_lat_bar.bar(combo_avg_names, combo_avgs_lat)
    combo_avgs_lat_bar.bar_label(bars2, fmt="%.2f ms")
    combo_avgs_lat_bar.set_ylabel("Latency (ms)")
    combo_avgs_lat_bar.set_title(f"Average Latencies(ms) for {NUM_TRIALS*2} Trials")

    avgs_rb_bar = fig8.add_subplot(111)
    bars3 = avgs_rb_bar.bar(avg_names[:12], avgs_rb)
    avgs_rb_bar.bar_label(bars3, fmt="%.2f ms")
    avgs_rb_bar.set_ylabel("Number of Bytes in Response")
    avgs_rb_bar.set_title(f"Average Number of Response Bytes for {NUM_TRIALS} Trials")

    combo_avgs_rb_bar = fig9.add_subplot(111)
    combo_avgs_rb_bar.bar(combo_avg_names_rb, combo_avgs_rb)
    combo_avgs_rb_bar.set_ylabel("Number of Bytes in Response")
    combo_avgs_rb_bar.set_title(f"Average Number of Response Bytes for {NUM_TRIALS*6} Trials")

    plt.show()

if __name__ == "__main__":
    main()
