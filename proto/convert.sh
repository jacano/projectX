mkdir proto3

protoc --plugin=protoc-gen-proto2_to_proto3 --proto2_to_proto3_out=proto3/ --proto_path=internal/ netmessages.proto
protoc --plugin=protoc-gen-proto2_to_proto3 --proto2_to_proto3_out=proto3/ --proto_path=internal/ cstrike15_usermessages.proto
