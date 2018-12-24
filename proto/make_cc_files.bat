@if not exist generated_proto mkdir generated_proto

@echo Running Protocol Buffer Compiler on netmessages_public.proto...
@protoc-3.6.1-win32\bin\protoc.exe --proto_path=public\ --cpp_out=generated_proto netmessages_public.proto

@echo Running Protocol Buffer Compiler on cstrike15_usermessages_public.proto...
@protoc-3.6.1-win32\bin\protoc.exe --proto_path=public\ --cpp_out=generated_proto cstrike15_usermessages_public.proto
