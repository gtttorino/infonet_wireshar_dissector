local infonet_info = 
{
    version = "0.0.1",
    author = "campagna.a@gtt.to.it",
    description = "This plugin parses UDP packets from Infonet protocol",
    repository = "https://github.com/avacee/xp11-Lua-Dissector"
}

set_plugin_info(infonet_info);

local subtree = nil;

local VALS_BOOL	= {[0] = "False", [1] = "True"}

local infonet2 = Proto("infonet2","InfoNET2");

infonet2.prefs.pred_port = Pref.uint("InfoNET Port",52000,"InfoNET port");

--local infonet2_header = ProtoField.string("infonet2.header","Header");
local infonet2_datetime = ProtoField.uint32("infonet2.datetime", "DataOra");
local infonet2_doors = ProtoField.bytes("infonet2.infonet2.doors", "Porte", base.SPACE);
local infonet2_fix = ProtoField.bytes("infonet2.infonet2.fix", "StatoGPS");
local infonet2_latitude = ProtoField.float("infonet2.infonet2.latitude", "Lat");
local infonet2_longitude = ProtoField.float("infonet2.infonet2.longitude", "Lon");
local infonet2_speed = ProtoField.uint8("infonet2.infonet2.speed", "VelKM");
local infonet2_loc = ProtoField.bytes("infonet2.infonet2.loc", "StatoLoc");
local infonet2_line = ProtoField.string("infonet2.infonet2.line", "Linea");
local infonet2_shift = ProtoField.string("infonet2.infonet2.shift", "Turno");
local infonet2_dest = ProtoField.string("infonet2.infonet2.dest", "FermataCapolinea");
local infonet2_current = ProtoField.string("infonet2.infonet2.current", "FermataCorrente");
local infonet2_next = ProtoField.string("infonet2.infonet2.next", "FermataProssima");
local infonet2_area = ProtoField.bytes("infonet2.infonet2.area", "StatoAreaFermata");
local infonet2_vehicle = ProtoField.uint16("infonet2.infonet2.vehicle", "Veicolo");
local infonet2_direction = ProtoField.char("infonet2.infonet2.direction", "Direzione");
local infonet2_driver = ProtoField.uint32("infonet2.infonet2.driver", "Autista");
local infonet2_company = ProtoField.string("infonet2.infonet2.company", "Azienda");
local infonet2_avm = ProtoField.string("infonet2.infonet2.avm", "AVM");
local infonet2_status = ProtoField.int8("infonet2.infonet2.status", "StatoVeicolo");
local infonet2_timing = ProtoField.int16("infonet2.infonet2.timing", "AnticipoRitardo");
local infonet2_trip = ProtoField.string("infonet2.infonet2.trip", "Corsa");

infonet2.fields = { 
    --infonet2_header,
    infonet2_datetime,
    infonet2_doors,
    infonet2_fix,
    infonet2_latitude,
    infonet2_longitude,
    infonet2_speed,
    infonet2_loc,
    infonet2_line,
    infonet2_shift,
    infonet2_dest,
    infonet2_current,
    infonet2_next,
    infonet2_area,
    infonet2_vehicle,
    infonet2_direction ,
    infonet2_driver ,
    infonet2_company,
    infonet2_avm,
    infonet2_status,
    infonet2_timing,
    infonet2_trip 
}

local function dissectINFONET2(tvb, pinfo, root_tree)

    print("enter function dissectINFONET2");
        
    pinfo.cols.info = "INFO_NET - INFO_NET2";

    local dataora = tvb:range(17):range(0,4);
    root_tree:add_le(infonet2_datetime, dataora);
    local porte = tvb:range(21):range(0,1);
    root_tree:add(infonet2_doors, porte);
    local fix = tvb:range(22):range(0,1);
    root_tree:add(infonet2_fix, fix);
    local lat = tvb:range(23):range(0,4);
    root_tree:add_le(infonet2_latitude, lat);
    local lon = tvb:range(27):range(0,4);
    root_tree:add_le(infonet2_longitude, lon);
    
    local speed = tvb:range(31,1);
    root_tree:add(infonet2_speed, speed);

    local loc = tvb:range(32):range(0,1);
    root_tree:add(infonet2_loc, loc);
    local line = tvb:range(33):range(0,6):stringz();
    root_tree:add(infonet2_line, line);
    local shift = tvb:range(40):range(0,6):stringz();
    root_tree:add(infonet2_shift, shift);

    local dest = tvb:range(47):range(0,8):stringz();
    root_tree:add(infonet2_dest, dest);
    local current = tvb:range(56):range(0,8):stringz();
    root_tree:add(infonet2_current, current);
    local next = tvb:range(65):range(0,8):stringz();
    root_tree:add(infonet2_next, next);
    local area = tvb:range(74):range(0,1);
    root_tree:add(infonet2_area, area);

    local veicolo = tvb:range(75):range(0,2);
    root_tree:add_le(infonet2_vehicle, veicolo);

    local direz = tvb:range(77):range(0,1);
    root_tree:add(infonet2_direction, direz);

    local driver = tvb:range(78):range(0,4);
    root_tree:add_le(infonet2_driver, driver);

    local company = tvb:range(82):range(0,4):stringz();
    root_tree:add(infonet2_company, company);

    local avm = tvb:range(86):range(0,3):stringz();
    root_tree:add(infonet2_avm, avm);

    local status = tvb:range(89,1);
    root_tree:add(infonet2_status, status);

    local timing = tvb:range(90,2);
    root_tree:add(infonet2_timing, timing);

    local corsa = tvb:range(92):range(0,8):stringz();
    root_tree:add(infonet2_trip, corsa);
    

    return true;
end

local subdissectors = {
    INFO_NET2 = dissectINFONET2
}

local function ValidatePacket(buffer, pinfo)

    local length = tonumber(buffer:len());
    print("buffer length: "..length);

    if length > 167 then
        print("LEN PACKET WRONG");
        return false;
    end
    
    local header = buffer(1,10):stringz();
    print("header: "..header);

    if subdissectors[header] == nil then
        print("subdissector: FALSE");
        return false;
    end
    if pinfo.dst_port ~= infonet2.prefs.pred_port then
        print("DEST_PORT: FALSE");
        return false;
    end
    if header == "INFO_NET2" and length ~= 101  then
        print("LEN INFO_NET2: FALSE");
        return false;
    end
    if header == "INFO_BIP" and length ~= 73 then
        print("LEN INFO_BIP: FALSE");
        return false;
    end
    if header == "INFO_BIP2" and length~= 167 then
        print("LEN INFO_BIP2: FALSE");
        return false;
    end
    if header == "CMD_BIP" and length ~= 20 then
        print("LEN INFO_BIP: FALSE");
        return false;
    end
    if header == "INFO_PAX" and length ~= 78 then
        print("LEN INFO_PAX: FALSE");
        return false;
    end

    return true;
end

function infonet2.dissector(buffer, pinfo, tree)
    
    if ValidatePacket(buffer, pinfo) == false then
        print("PACKET NOT VALID");
        return false;
    end

    local header = buffer(1, 10):stringz();
    pinfo.cols.protocol = "infonet." .. header:lower();
    
    if header == "INFO_NET2" then
        subtree = tree:add(infonet2, buffer(), "InfoNET (" .. header .. ") Packet Length " .. buffer:len());
    end

    return subdissectors[header](buffer, pinfo, subtree);
end

local udp_encap_table = DissectorTable.get("udp.port");
udp_encap_table:add(infonet2.prefs.pred_port, infonet2);
