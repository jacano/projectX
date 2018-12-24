@if not exist generated_proto_cs mkdir generated_proto_cs

@echo Running Protocol Buffer Compiler on netmessages_public.proto...
@protoc-3.6.1-win32\bin\protoc.exe --proto_path=internal\ --csharp_out=generated_proto_cs netmessages.proto

@echo Running Protocol Buffer Compiler on cstrike15_usermessages_public.proto...
@protoc-3.6.1-win32\bin\protoc.exe --proto_path=internal\ --csharp_out=generated_proto_cs cstrike15_usermessages.proto
