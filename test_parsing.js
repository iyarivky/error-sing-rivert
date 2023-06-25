//let urlString = "vmess://eyJhZGQiOiAic2cyLXJheS5pcHNlcnZlcnMueHl6IiwgImhvc3QiOiAic25pLmNsb3VkZmxhcmUuY29tIiwgImFpZCI6IDAsICJ0eXBlIjogIiIsICJwYXRoIjogIi9KQUdPQU5TU0gvIiwgIm5ldCI6ICJ3cyIsICJwcyI6ICJqYWdvYW5zc2gtZ29kZGFtbiIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAibm9uZSIsICJwb3J0IjogIjQ0MyIsICJ2IjogIjIiLCAiaWQiOiAiNGE0NWU0NzctY2ZhMS00YTBmLWEwYjAtZTQ1MTczYzYyZjViIn0=";
let urlString = "https://d4cbf663-6950-4c64-8a52-f8b82a02e031@sg4-ws.xvless.xyz:443?path=%2Fwebsocket&security=none&encryption=none&host=sg4-ws.xvless.xyz&type=ws&sni=sni.cloudflare.net#sshocean-legendaplis"
const urlObj = new URL(urlString);
console.log(urlObj)

const protocol = urlObj.protocol;
const hostname = urlObj.hostname;
const pathname = urlObj.pathname;
const searchParams = urlObj.searchParams;
//parsedUrl.searchParams.get("type")

console.log(protocol); 
console.log(hostname);
console.log(urlObj.username);
console.log(urlObj.href);
console.log(urlObj.port)
console.log(searchParams.get("type"));
//console.log(searchParams.get("param2"));