import json
import sys
from client import SchnorrSignature, Secp256k1Curve

def handle_request(req):
    method = req.get("method")
    params = req.get("params", {})
    req_id = req.get("id")

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "verify_schnorr_signature",
                        "description": "Verify Schnorr digital signature on secp256k1 curve",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "pub_x": {"type": "string"},
                                "pub_y": {"type": "string"},
                                "message": {"type": "string"},
                                "r_x": {"type": "string"},
                                "r_y": {"type": "string"},
                                "s": {"type": "string"}
                            },
                            "required": ["pub_x", "pub_y", "message", "r_x", "r_y", "s"]
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "verify_schnorr_signature":
            pub = (int(args["pub_x"], 16), int(args["pub_y"], 16))
            sig = ((int(args["r_x"], 16), int(args["r_y"], 16)), int(args["s"], 16))
            ok = SchnorrSignature.verify(pub, args["message"].encode("utf-8"), sig)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps({"valid": ok})}]}
            }
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}

def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            res = handle_request(req)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
