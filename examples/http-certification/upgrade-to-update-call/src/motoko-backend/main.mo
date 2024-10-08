import Text "mo:base/Text";

actor Http {
  type HeaderField = (Text, Text);

  type HttpRequest = {
    method : Text;
    url : Text;
    headers : [HeaderField];
    body : Blob;
    certificate_version : ?Nat16;
  };

  type HttpUpdateRequest = {
    method : Text;
    url : Text;
    headers : [HeaderField];
    body : Blob;
  };

  type HttpResponse = {
    status_code : Nat16;
    headers : [HeaderField];
    body : Blob;
    upgrade : ?Bool;
  };

  type HttpUpdateResponse = {
    status_code : Nat16;
    headers : [HeaderField];
    body : Blob;
  };

  public query func http_request(_req: HttpRequest) : async HttpResponse {
    return {
      status_code = 200;
      headers = [];
      body = "";
      upgrade = ?true;
    };
  };

  public func http_request_update(_req: HttpUpdateRequest) : async HttpUpdateResponse {
    return {
      status_code = 418;
      headers = [];
      body = Text.encodeUtf8("I'm a teapot");
    };
  };
};
