import {
  verifyRequestResponsePair,
  Request,
  Response,
} from "@dfinity/response-verification";

function createHeaderField(name: string, value: string): string {
  return `${name}=:${value}:`;
}

const request: Request = { headers: [] };

const certificate_header = [
  createHeaderField(
    "certificate",
    "2dn3omR0cmVlgwGDAYMBgwJIY2FuaXN0ZXKDAYMBggRYIKuhi/JO9sgi75t/kA+9DehOG/7+55Tn93zAZjy0FxlYgwGCBFgghPQ1K4RWkme7KUg5sb8st/AHihkFI9nQvORSLZfQQs+DAYIEWCApRtZD4YdE3Pv3i1wzH54QQQmwjiOQhUho+5OXhy6P5IMCSgAAAAAAAAAIAQGDAYMBgwGDAk5jZXJ0aWZpZWRfZGF0YYIDWCBTsL26f5jMA0Pb74JZph9tnsmBElfu1zaXUteehhyzKIIEWCD9W1lFl1jIr+yvcoXaNZ5LWtuUX7hqPB8O/ZlsIalpOIIEWCDocoQwWZif2PSwUdHEIIM1dZMucMxvDi0O+T1GHaA/KYIEWCBm1Q7knXSb264KfrMqN2Mv5obIYU/nVNweZHb48M1SioIEWCD8uEni9w/T9dTT7BwMCDed0wGxYCvRjDUS96He5rJ6HYIEWCB4rK9xW2Gl0fgEYDXDHv4NkLW5Vwk7Iv6MWkRau3Je3oIEWCCC/8uL2dzreqXFVvI33CUbXezo4o1y0/TcwUKxC9dTYYMBggRYIAsvEs+DqKM5aRwNOb44QyzuGmTajjiYu2mv22lwgjxegwJEdGltZYIDSZfG4/fnn46TF2lzaWduYXR1cmVYMLarhuyVeRYdY0KNVdBFmR1ciNw0w2qOcFsjPHgQODmyNobn+TLS5/beBMxSs3dXYA=="
  ),
  createHeaderField(
    "tree",
    "2dn3gwJLaHR0cF9hc3NldHODAYIEWCAzGcq/JXaG1HIcnLqbOMUxuHmcZOEtMDsnl/LC3U2u8oMBggRYINARrQ7YXMe7oEJsuG4PLfVaX8GIw918m7HyvCMesqFQgwGCBFggYr721CUplXO6PG3U6ae6+aRGZCe3tfopRtrKu+cbD2GDAYIEWCBSY8jBPsvtZ8fI78lmcuU8Whq2Sp3g+9jUbgT4IGIc24MBgwGCBFgguwMPt5ABz2KUR5huA359yu/U8sV5vVsuAKmLaRr6cZqDAYIEWCDiVpABWHHeaLyLuhAGa5LGnfCToTJLPQOA3xuFj9KwwIMBggRYIMaHrSJxI7nZI4mhGc08Gxnt3LobpjLElnmJqnnWfJJsgwGCBFggZpjDFPEIUXDyLeTgvjYU/OV1mXH+247wRmsPV/cWh9GDAYIEWCD7cHynryxbTMXji9T94Kzb9LR0BX1xD08jd50IVuZKkIMBggRYIBqH/ehKNlzjsvoHXKp6XHHFGzorIR5lDdJEFsWVLeWDgwGCBFggujGGLJsxXiwF7fJ19Zurljf9CUzdoF+l5sdVRklaobGDAYIEWCCqPigqj6kF8A1trYxtOd+QaOJq1+YiKLaZ4t3PzI7mGIMCTC9mYXZpY29uLmljb4IDWCCrKCW+nJJIulp9gWjj4Lo9NKvECTZUATB1oa7ApMXZ1IIEWCDXKefy8xJco0VpRwt4qyQBj4E0O9d82SE1SmnIkqpR1A=="
  ),
].join(",");
const response: Response = {
  headers: [["Ic-Certificate", certificate_header]],
};

const result = verifyRequestResponsePair(request, response);

console.log("Result", result);
