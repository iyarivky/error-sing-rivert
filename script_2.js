function parseUrls(vrayUrls,httpUrls) {
  const vrayUrlsLength = vrayUrls.length;
  const results = [];

  const parseVmessUrl = (vrayParsedUrl,httpParsedUrl) => {
    let href = vrayParsedUrl.href
    let encoded = href.substring(8);
    let decodeResult = atob(encoded);
    let parsedJSON = JSON.parse(decodeResult);
    const configResult = {
      tag: parsedJSON.ps,
      type: "vmess",
      server: parsedJSON.add,
      server_port: parseInt(parsedJSON.port, 10),
      uuid: parsedJSON.id,
      security: "auto",
      alter_id: parsedJSON.aid,
      global_padding: false,
      authenticated_length: true,
      multiplex: {
        enable: false,
        protocol: "smux",
        max_streams: 32
      }
    };

    if (parsedJSON.port === "443" || parsedJSON.tls === "tls") {
      configResult.tls = {
        enable: true,
        server_name: parsedJSON.sni || parsedJSON.add,
        insecure: true,
        disable_sni: false
      };
    }

    if (parsedJSON.net === "ws") {
      configResult.transport = {
        type: parsedJSON.net,
        path: parsedJSON.path,
        headers: {
          Host: parsedJSON.host || parsedJSON.add
        }
      };
    } else if (parsedJSON.net === "grpc") {
      configResult.transport = {
        type: parsedJSON.net,
        service_name: parsedJSON.path
      };
    }

    return configResult;
  };

  const parseVlessUrl = (vrayParsedUrl,httpParsedUrl) => {
    const configResult = {
      tag: httpParsedUrl.hash.substring(1),
      type: "vless",
      server: httpParsedUrl.hostname,
      server_port: parseInt(httpParsedUrl.port, 10),
      uuid: httpParsedUrl.username,
      flow: "",
      packet_encoding: "xudp",
      multiplex: {
        enable: false,
        protocol: "smux",
        max_streams: 32
      }
    };

    if (httpParsedUrl.port === "443" || httpParsedUrl.searchParams.get("security") === "tls") {
      configResult.tls = {
        enable: true,
        server_name: httpParsedUrl.searchParams.get("sni"),
        insecure: true,
        disable_sni: false
      };
    }

    const transportTypes = {
      ws: {
        type: httpParsedUrl.searchParams.get("type"),
        path: httpParsedUrl.searchParams.get("path"),
        headers: {
          Host: httpParsedUrl.searchParams.get("host")
        }
      },
      grpc: {
        type: httpParsedUrl.searchParams.get("type"),
        service_name: httpParsedUrl.searchParams.get("serviceName")
      }
    };

    configResult.transport = transportTypes[httpParsedUrl.searchParams.get("type")];

    return configResult;
  };

  const parseTrojanUrl = (vrayParsedUrl,httpParsedUrl) => {
    const configResult = {
      tag: httpParsedUrl.hash.substring(1),
      type: "trojan",
      server: httpParsedUrl.hostname,
      server_port: parseInt(httpParsedUrl.port, 10),
      password: httpParsedUrl.username,
      multiplex: {
        enable: false,
        protocol: "smux",
        max_streams: 32
      }
    };

    if (httpParsedUrl.port === "443" || httpParsedUrl.searchParams.get("security") === "tls") {
      configResult.tls = {
        enable: true,
        server_name: httpParsedUrl.searchParams.get("sni"),
        insecure: true,
        disable_sni: false
      };
    }

    const transportTypes = {
      ws: {
        type: httpParsedUrl.searchParams.get("type"),
        path: httpParsedUrl.searchParams.get("path"),
        headers: {
          Host: httpParsedUrl.searchParams.get("host")
        }
      },
      grpc: {
        type: httpParsedUrl.searchParams.get("type"),
        service_name: httpParsedUrl.searchParams.get("serviceName")
      }
    };

    configResult.transport = transportTypes[httpParsedUrl.searchParams.get("type")];

    return configResult;
  };

  const parseShadowsocksUrl = (vrayParsedUrl,httpParsedUrl) => {
    const configResult = {
      tag: httpParsedUrl.hash.replace("#", ""),
      type: httpParsedUrl.protocol.replace(":", ""),
      server: httpParsedUrl.hostname,
      server_port: parseInt(httpParsedUrl.port, 10)
    };
    return configResult;
  };
  const parseShadowsocksRUrl = (vrayParsedUrl,httpParsedUrl) => {
    const configResult = {
      tag: httpParsedUrl.hash.replace("#", ""),
      type: httpParsedUrl.protocol.replace(":", ""),
      server: httpParsedUrl.hostname,
      server_port: parseInt(httpParsedUrl.port, 10)
    };
    return configResult;
  };
  const parseSocksUrl = (vrayParsedUrl,httpParsedUrl) => {
    const configResult = {
      tag: httpParsedUrl.hash.replace("#", ""),
      type: httpParsedUrl.protocol.replace(":", ""),
      server: httpParsedUrl.hostname,
      server_port: parseInt(httpParsedUrl.port, 10)
    };
    return configResult;
  };
  const parseHttpUrl = (vrayParsedUrl,httpParsedUrl) => {
    const configResult = {
      tag: httpParsedUrl.hash.replace("#", ""),
      type: httpParsedUrl.protocol.replace(":", ""),
      server: httpParsedUrl.hostname,
      server_port: parseInt(httpParsedUrl.port, 10)
    };
    return configResult;
  };
  // for (let i = 0; i < urlStrings.length; i++)
  // for (const urlString of urlStrings) <= slow

  const protocolMap = {
    "vmess:": parseVmessUrl,
    "vless:": parseVlessUrl,
    "trojan:": parseTrojanUrl,
    "ss:": parseShadowsocksUrl,
    "ssr:": parseShadowsocksRUrl,
    "socks5:": parseSocksUrl,
    "http:": parseHttpUrl
  };
  
  for (let i = 0; i < vrayUrlsLength; i++) {
    const vrayString = vrayUrls[i];
    const httpString = httpUrls[i];
    const vrayParsedUrl = new URL(vrayString);
    const httpParsedUrl = new URL(httpString);
  
    let configResult;
  
    const protocolHandler = protocolMap[vrayParsedUrl.protocol];
    if (protocolHandler) {
      configResult = protocolHandler(vrayParsedUrl, httpParsedUrl);
    } else {
      console.log("Unsupported Protocol!")
    }
    const panjangResult = results.length;
    results[panjangResult] = configResult;
  }
  return results;
}

const vrayUrls = [
  "vmess://eyJhZGQiOiAic2cyLXJheS5pcHNlcnZlcnMueHl6IiwgImhvc3QiOiAic25pLmNsb3VkZmxhcmUuY29tIiwgImFpZCI6IDAsICJ0eXBlIjogIiIsICJwYXRoIjogIi9KQUdPQU5TU0gvIiwgIm5ldCI6ICJ3cyIsICJwcyI6ICJqYWdvYW5zc2gtZ29kZGFtbiIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAibm9uZSIsICJwb3J0IjogIjQ0MyIsICJ2IjogIjIiLCAiaWQiOiAiNGE0NWU0NzctY2ZhMS00YTBmLWEwYjAtZTQ1MTczYzYyZjViIn0=",
  "vmess://eyJhZGQiOiJ1czIub2NlaXMubmV0IiwiYWlkIjoiMCIsImFscG4iOiIiLCJmcCI6IiIsImhvc3QiOiIiLCJpZCI6ImRhY2Y2MzQwLTA5ZmQtMTFlZS1iMjM2LTIwNWM2ZDVmNWQ3OCIsIm5ldCI6IndzIiwicGF0aCI6Ii92bXdzIiwicG9ydCI6IjQ0MyIsInBzIjoiVVNBK1ZNRVNTLVdTKDIwMjMtMDYtMjApIiwic2N5Ijoibm9uZSIsInNuaSI6IndoYXRzYXBwLm5ldCIsInRscyI6InRscyIsInR5cGUiOiIiLCJ2IjoiMiJ9",
  "vmess://eyJhZGQiOiJ1czIub2NlaXMubmV0IiwiYWlkIjoiMCIsImFscG4iOiIiLCJmcCI6IiIsImhvc3QiOiIiLCJpZCI6ImRhY2Y2MzQwLTA5ZmQtMTFlZS1iMjM2LTIwNWM2ZDVmNWQ3OCIsIm5ldCI6IndzIiwicGF0aCI6Ii92bXdzIiwicG9ydCI6IjgwIiwicHMiOiJVU0ErVk1FU1MtV1MgTlRMUygyMDIzLTA2LTIwKSIsInNjeSI6Im5vbmUiLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIifQ==",
  "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo",
  "vless://d4cbf663-6950-4c64-8a52-f8b82a02e031@sg4-ws.xvless.xyz:80?path=%2Fwebsocket&security=none&encryption=none&host=sg4-ws.xvless.xyz&type=ws&sni=sni.cloudflare.net#sshocean-legendaplis",
  "vless://f746cd36-f565-444b-8bb8-6043c79eb3da@id1-grpc.xvless.xyz:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-legendano",
  "trojan://a758ef8c-f06c-4e9d-8f0b-51633db51817@idt6.sshocean.net:443?security=tls&headerType=none&type=tcp&sni=sni.cloudflare.net#sshocean-kenapalegenda_trojan",
  "trojan://6d9fdac3-d74b-435f-aa6b-5fbf36e06853@sg1.xvless.xyz:443?host=sg1.xvless.xyz&path=%2Ftrojan&sni=sg1.xvless.xyz&type=ws#sshocean-ainian",
  "trojan://dbedf072-d917-41cd-b106-3aa3bb2f29a4@idt4.sshocean.net:443?mode=gun&security=tls&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-pengentest_Trojan_gRPC"
];
const httpUrls = vrayUrls.map(urlString => urlString.replace(/^[^:]+(?=:\/\/)/, 'ftp')); //convert v2ray urls to http url since WHATWG URL API is suck when dealing with other protocol

const startTime = performance.now();
const results = parseUrls(vrayUrls,httpUrls);
const endTime = performance.now();
let diff = endTime - startTime;
const jsonResult = JSON.stringify(results, null, 4);
console.log(jsonResult);
console.log(diff, "ms");
