@if exist generated_proto_cs rmdir /s /q generated_proto_cs
@if not exist generated_proto_cs mkdir generated_proto_cs

@echo Running Protogen on netmessages_public.proto...
@protogen-2.3.16\net462\protogen.exe --proto_path=public\ --csharp_out=generated_proto_cs\ netmessages_public.proto

@echo Running Protogen on cstrike15_usermessages_public.proto...
@protogen-2.3.16\net462\protogen.exe --proto_path=public\ --csharp_out=generated_proto_cs\ cstrike15_usermessages_public.proto
