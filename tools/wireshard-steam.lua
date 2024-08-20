-- A wireguard dissector for steam
steam_proto        = Proto("steam", "Steam Network Protocol")
f_msg_type         = ProtoField.uint8("steam.MessageType", "MessageType", base.DEC)
f_is_proto         = ProtoField.bool("steam.IsProto", "IsProto")
f_header_proto     = ProtoField.bytes("steam.Header", "Header")
f_header_body      = ProtoField.bytes("steam.Body", "Body")

steam_proto.fields = { f_msg_type, f_is_proto, f_header_proto, f_header_body }

local f_payload    = Field.new("websocket.payload")
local f_opcode     = Field.new("websocket.opcode")
function steam_proto.dissector(buffer, pinfo, tree)
  local websocket_payload_table = { f_payload() };
  local opcode = f_opcode();
  if opcode.value == 2 then
    for counter, websocket_payload in ipairs(websocket_payload_table) do
      if websocket_payload then
        local data = websocket_payload.range:bytes();
        local subtree = tree:add(steam_proto, "Steam Protocol Data")
        local msg_type = data:le_uint(0, 4)
        local header_length = data:le_uint(4, 4)
        subtree:add(f_msg_type, websocket_payload.range(0, 3), bit32.band(msg_type, bit32.bnot(0x80000000)))
        subtree:add(f_is_proto, websocket_payload.range(3, 1), bit32.band(msg_type, 0x80000000) == 0x80000000)
        if header_length > 0 then
          subtree:add(f_header_proto, websocket_payload.range(8, header_length),
            data:subset(8, header_length):raw())
        end
        if data:len() > header_length + 8 then
          subtree:add(f_header_body, websocket_payload.range(8 + header_length),
            data:subset(8 + header_length, data:len() - 8 - header_length):raw())
        end
      end
    end
  end
end

register_postdissector(steam_proto)
