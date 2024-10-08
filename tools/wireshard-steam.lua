-- A wireguard dissector for steam
do
  local is_proto_mask      = 0x80000000;
  local msg_type_mask      = bit32.bnot(0x80000000);

  steam_outer_proto        = Proto("_steam", "Steam Network Protocol Outer")
  multi_proto              = Proto("steam_multi", "Steam Network Protocol Multi")

  steam_proto              = Proto("steam", "Steam Network Protocol")
  f_msg_type               = ProtoField.uint32("steam.messageType", "MessageType", base.DEC, nil, msg_type_mask)
  f_is_proto               = ProtoField.bool("steam.proto", "IsProto", base.DEC, nil, is_proto_mask)
  f_header_len_proto       = ProtoField.uint32("steam.header.length", "HeaderLength", base.DEC)
  f_header_proto           = ProtoField.bytes("steam.header", "Header")
  f_header_body            = ProtoField.bytes("steam.body", "Body")
  f_header_body_gc_type    = ProtoField.uint32("steam.Body.gc.messageType", "GC Message Type", base.DEC, nil,
    msg_type_mask)

  steam_proto.fields       = { f_msg_type, f_is_proto, f_header_proto, f_header_body, f_header_len_proto }

  local protobuf_dissector = Dissector.get("protobuf")

  local f_payload          = Field.new("websocket.payload")
  local f_opcode           = Field.new("websocket.opcode")

  function steam_outer_proto.dissector(buffer, pinfo, tree)
    local websocket_payload_table = { f_payload() };
    local opcode = f_opcode();
    if opcode.value == 2 then
      for counter, websocket_payload in ipairs(websocket_payload_table) do
        if websocket_payload then
          local subtree = tree:add(steam_proto, buffer, "Steam Protocol Data")
          steam_proto.dissector:call(websocket_payload.range:tvb(), pinfo, subtree)
        end
      end
    end
  end

  local f_gc_msg_type = Field.new("pbf.CMsgGCClient.msgtype")

  function steam_proto.dissector(buffer, pinfo, tree)
    local data = buffer:bytes();
    if data:len() < 8 then
      return
    end
    local msg_type = data:le_uint(0, 4)
    local header_length = data:le_uint(4, 4)
    local msg_is_protobuf = bit32.band(msg_type, is_proto_mask) == is_proto_mask;
    tree:add(f_msg_type, buffer(0, 4), msg_type)
    tree:add(f_is_proto, buffer(0, 4), msg_type)
    tree:add(f_header_len_proto, buffer(4, 4), header_length)
    if header_length > 0 then
      if msg_is_protobuf then
        pinfo.private["pb_msg_type"] = "message,CMsgProtoBufHeader"
        protobuf_dissector:call(buffer(8, header_length):tvb(), pinfo, tree)
      else
        tree:add(f_header_proto, buffer(8, header_length))
      end
    end
    if data:len() > header_length + 8 then
      local msg_body_range = buffer(8 + header_length)
      if msg_is_protobuf then
        local msg_type_dec = bit32.band(msg_type, msg_type_mask);
        if msg_type_dec == 1 then
          multi_proto.dissector:call(msg_body_range:tvb(), pinfo, tree)
        else
          if msg_type_protos[msg_type_dec] ~= nil then
            pinfo.private["pb_msg_type"] = "message," .. msg_type_protos[msg_type_dec]
          else
            pinfo.private["pb_msg_type"] = nil
          end
          protobuf_dissector:call(msg_body_range:tvb(), pinfo, tree)
          if msg_type_protos[msg_type_dec] == "CMsgGCClient" then
            local nested_msg_type = f_gc_msg_type();
            tree:add(f_msg_type, nested_msg_type.range, nested_msg_type.value)
            tree:add(f_is_proto, nested_msg_type.range, nested_msg_type.value)
          end
        end
      else
        tree:add(f_header_body, msg_body_range)
      end
    end
  end

  register_postdissector(steam_outer_proto)
  local protobuf_field_table = DissectorTable.get("protobuf_field")
  protobuf_field_table:add("CMsgGCClient.payload", steam_proto)

  msg_type_protos    = {
    [1] = "CMsgMulti",
    [5452] = "CMsgGCClient",
    [5453] = "CMsgGCClient",
    [5410] = "CMsgClientGamesPlayed"
  }

  local f_multi_len  = Field.new("pbf.CMsgMulti.size_unzipped")
  local f_multi_body = Field.new("pbf.CMsgMulti.message_body")
  function multi_proto.dissector(buffer, pinfo, tree)
    pinfo.private["pb_msg_type"] = "message,CMsgMulti"
    protobuf_dissector:call(buffer, pinfo, tree)
    local unzipped_data
    if f_multi_len() then
      unzipped_data = f_multi_body().range:uncompress("message_body_decompressed")
    else
      unzipped_data = f_multi_body().range
    end
    while unzipped_data:len() > 4 do
      local size = unzipped_data:bytes():le_uint(0, 4)
      local chunk_data = unzipped_data(4, size)
      local subtree = tree:add(steam_proto, buffer, "Nested")
      steam_proto.dissector:call(chunk_data:tvb(), pinfo, subtree)
      if 4 + size >= unzipped_data:len() then
        break
      end
      unzipped_data = unzipped_data(4 + size)
    end
  end
end
