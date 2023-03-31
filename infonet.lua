local infonet_info = {
    version = "0.8.7",
    author = "campagna.a@gtt.to.it",
    description = "This plugin parses UDP packets from Infonet protocol",
    repository = "https://github.com/gtttorino/infonet_wireshark_dissector"
}

set_plugin_info(infonet_info);
local pred_port = 52000;
local infonet = Proto("infonet", "InfoNET");
infonet.prefs.pred_port = Pref.uint("InfoNET Port", pred_port, "InfoNET port");

local VALS_BOOL = {
    [0] = "False",
    [1] = "True"
}

local VALS_AREA = {
    [0] = "Non in area di fermata",
    [1] = "Ingresso area di fermata",
    [2] = "Uscita area di fermata",
    [3] = "Fermata in corso",
    [4] = "In area di fermata"
}

local VALS_AVM = {
    [0] = "OPAVM (GTT/Leonardo/Mizar)",
    [1] = "AESYS (ExtraTo)",
    [2] = "Divitech",
    [3] = "OPAVM (Leonardo)",
    [4] = "AEP",
    [6] = "TEQ",
    [99] = "Altro / non significativo"
}

local VALS_STATUS = {
    [0] = "Veicolo in servizio",
    [1] = "Capolinea",
    [2] = "Entrata in servizio",
    [3] = "Uscita dal servizio",
    [4] = "Manutenzione/Deposito/Altro",
    [6] = "Spegnimento"
}

local VALS_COMPANY = {
    [0] = "Sconosciuta",
    [1] = "GTT"
}

-- INFONET2
local infonet2 = Proto("infonet2", "InfoNET2");
infonet2.prefs.pred_port = Pref.uint("InfoNET Port", pred_port, "InfoNET port");
-- local infonet2_header = ProtoField.string("infonet2.header","Header");
local infonet2_datetime = ProtoField.uint32("infonet2.datetime", "DataOra");
local infonet2_doors = ProtoField.uint8("infonet2.doors", "Porte");
local infonet2_fix = ProtoField.int8("infonet2.fix", "StatoGPS");
local infonet2_latitude = ProtoField.float("infonet2.latitude", "Lat");
local infonet2_longitude = ProtoField.float("infonet2.longitude", "Lon");
local infonet2_speed = ProtoField.uint8("infonet2.speed", "VelKM");
local infonet2_loc = ProtoField.bytes("infonet2.loc", "StatoLoc");
local infonet2_line = ProtoField.string("infonet2.line", "Linea");
local infonet2_shift = ProtoField.string("infonet2.infonet2.shift", "Turno");
local infonet2_dest = ProtoField.string("infonet2.dest", "FermataCapolinea");
local infonet2_current = ProtoField.string("infonet2.current", "FermataCorrente");
local infonet2_next = ProtoField.string("infonet2.next", "FermataProssima");
local infonet2_area = ProtoField.string("infonet2.area", "StatoAreaFermata");
local infonet2_vehicle = ProtoField.uint16("infonet2.vehicle", "Veicolo");
local infonet2_direction = ProtoField.char("infonet2.direction", "Direzione");
local infonet2_driver = ProtoField.uint32("infonet2.driver", "Autista");
local infonet2_company = ProtoField.string("infonet2.company", "Azienda");
local infonet2_avm = ProtoField.string("infonet2.avm", "AVM");
local infonet2_status = ProtoField.string("infonet2.status", "StatoVeicolo");
local infonet2_timing = ProtoField.int16("infonet2.timing", "AnticipoRitardo");
local infonet2_trip = ProtoField.string("infonet2.trip", "Corsa");
infonet2.fields = { -- infonet2_header,
infonet2_datetime, infonet2_doors, infonet2_fix, infonet2_latitude, infonet2_longitude, infonet2_speed, infonet2_loc,
infonet2_line, infonet2_shift, infonet2_dest, infonet2_current, infonet2_next, infonet2_area, infonet2_vehicle,
infonet2_direction, infonet2_driver, infonet2_company, infonet2_avm, infonet2_status, infonet2_timing, infonet2_trip}

local function dissectINFONET2(tvb, pinfo, root_tree)

    print("enter function dissectINFONET2");

    local inf2 = true;
    if (tvb:range(1, 10):stringz():sub(-1) ~= "2") then
        inf2 = false;
    end
    if (inf2 == true) then
        pinfo.cols.info = "infonet-INFO_NET2";
    else
        pinfo.cols.info = "infonet-INFO_NET";
    end

    local dataora = tvb:range(17):range(0, 4);
    root_tree:add_le(infonet2_datetime, dataora);
    local porte = tvb:range(21):range(0, 1);
    root_tree:add(infonet2_doors, porte);
    local fix = tvb:range(22):range(0, 1);
    root_tree:add(infonet2_fix, fix);
    local lat = tvb:range(23):range(0, 4);
    root_tree:add_le(infonet2_latitude, lat);
    local lon = tvb:range(27):range(0, 4);
    root_tree:add_le(infonet2_longitude, lon);

    local speed = tvb:range(31, 1);
    root_tree:add(infonet2_speed, speed);

    local loc = tvb:range(32):range(0, 1);
    root_tree:add(infonet2_loc, loc);

    local line = tvb:range(33):range(0, 6):stringz();
    if (inf2 == false) then
        line = tvb:range(33):range(0, 4):stringz();
    end
    root_tree:add(infonet2_line, line);

    local shift = tvb:range(40):range(0, 6):stringz();
    if (inf2 == false) then
        shift = tvb:range(38):range(0, 4):stringz();
    end
    root_tree:add(infonet2_shift, shift);

    local offset = 47;
    if (inf2 == false) then
        offset = 42;
    end
    local dest = tvb:range(offset):range(0, 8):stringz();
    root_tree:add(infonet2_dest, dest);

    offset = 56;
    if (inf2 == false) then
        offset = 51;
    end
    local current = tvb:range(offset):range(0, 8):stringz();
    root_tree:add(infonet2_current, current);

    offset = 65;
    if (inf2 == false) then
        offset = 60;
    end
    local next = tvb:range(offset):range(0, 8):stringz();
    root_tree:add(infonet2_next, next);

    offset = 74;
    if (inf2 == false) then
        offset = 69;
    end
    local area = tvb:range(offset):range(0, 1);
    area = area:int();
    if (area < 0) then
        area = "Informazione non disponibile";
    else
        area = VALS_AREA[area];
    end
    root_tree:add(infonet2_area, area);

    offset = 75;
    if (inf2 == false) then
        offset = 70;
    end
    local veicolo = tvb:range(offset):range(0, 2);
    root_tree:add_le(infonet2_vehicle, veicolo);

    offset = 77;
    if (inf2 == false) then
        offset = 72;
    end
    local direz = tvb:range(offset):range(0, 1);
    root_tree:add(infonet2_direction, direz);

    offset = 78;
    if (inf2 == false) then
        offset = 73;
    end
    local driver = tvb:range(offset):range(0, 4);
    root_tree:add_le(infonet2_driver, driver);

    if (inf2 == true) then
        local company = tvb:range(82):range(0, 4):stringz();
        company = tonumber(company);
        if (company < 0) then
            company = "Sconosciuta";
        else
            company = VALS_COMPANY[company];
        end
        root_tree:add(infonet2_company, company);

        local avm = tvb:range(86):range(0, 3):stringz();
        root_tree:add(infonet2_avm, VALS_AVM[tonumber(avm)]);

        local status = tvb:range(89, 1);
        print("STATUS: " .. status);
        status = status:int();
        if (status < 0) then
            status = "Sconosciuto";
        else
            status = VALS_STATUS[status];
        end
        root_tree:add(infonet2_status, status);

        local timing = tvb:range(90, 2);
        root_tree:add(infonet2_timing, timing);

        local corsa = tvb:range(92):range(0, 8):stringz();
        root_tree:add(infonet2_trip, corsa);
    end

    return true;
end

-- INFOBIP
local infobip = Proto("infobip", "infobip");
infobip.prefs.pred_port = Pref.uint("InfoNET Port", pred_port, "InfoNET port");
local infobip_datetime = ProtoField.uint32("infobip.datetime", "DataOra");
local infobip_applMode = ProtoField.uint8("infobip.applmode", "ApplMode");
local infobip_applStatus = ProtoField.uint8("infobip.applstatus", "ApplStatus");
local infobip_serviceStatus = ProtoField.uint8("infobip.servicestatus", "ServiceStatus");
local infobip_cnvTotal = ProtoField.uint8("infobip.cnvtotal", "CnvTotal");
local infobip_cnvServiceCount = ProtoField.uint8("infobip.cnvservicecount", "CnvServiceCount");
local infobip_cnvStatus = ProtoField.uint16("infobip.cnvstatus", "CnvStatus");
local infobip_localityType = ProtoField.uint8("infobip.localitytype", "LocalityType");
local infobip_localityValue = ProtoField.uint16("infobip.localityvalue", "LocalityValue");
local infobip_messageMode = ProtoField.uint8("infobip.messagemode", "MessageMode");
local infobip_messageText = ProtoField.string("infobip.messageText", "MessageText");
local infobip_fix = ProtoField.string("infobip.fix", "Fix");
local infobip_latitude = ProtoField.float("infobip.latitude", "Latitude");
local infobip_longitude = ProtoField.float("infobip.longitude", "Longitude");
local infobip_gpsSignalLevel = ProtoField.uint8("infobip.gpssignallevel", "GpsSignalLevel");
local infobip_gprsSignalLevel = ProtoField.uint8("infobip.gprssignallevel", "GprsSignalLevel");
local infobip_wiFiSignalLevel = ProtoField.uint8("infobip.wifisignallevel", "WiFiSignalLevel");
local infobip_ipLinkStatus = ProtoField.uint8("infobip.iplinkstatus", "IpLinkStatus");
local infobip_localityCodeBip = ProtoField.uint32("infobip.localitycodeBip", "LocalityCodeBip");
local infobip_localityDescriptionBip = ProtoField.string("infobip.messagetext", "MessageText");
local infobip_lineCodeBip = ProtoField.uint32("infobip.linecodebip", "LineCodeBip");
local infobip_lineDescriptionBip = ProtoField.string("infobip.linedescriptionbip", "LineDescriptionBip");
infobip.fields = {infobip_datetime, infobip_applMode, infobip_applStatus, infobip_serviceStatus, infobip_cnvTotal,
                  infobip_cnvServiceCount, infobip_cnvStatus, infobip_localityType, infobip_localityValue,
                  infobip_messageMode, infobip_messageText, infobip_fix, infobip_latitude, infobip_longitude,
                  infobip_gpsSignalLevel, infobip_gprsSignalLevel, infobip_wiFiSignalLevel, infobip_ipLinkStatus,
                  infobip_localityCodeBip, infobip_localityDescriptionBip, infobip_lineCodeBip,
                  infobip_lineDescriptionBip}

local function dissectINFOBIP1(tvb, pinfo, root_tree)

    print("enter function dissectINFOBIP1");

    pinfo.cols.info = "infonet-INFO_BIP";

    local dataora = tvb:range(17, 4);
    local applmode = tvb:range(21, 1);
    local applStatus = tvb:range(22, 1);
    local serviceStatus = tvb:range(23, 1);
    local cnvTotal = tvb:range(24, 1);
    local cnvServiceCount = tvb:range(25, 1);
    local cnvStatus = tvb:range(26, 2);
    local localityType = tvb:range(28, 1);
    local localityValue = tvb:range(29, 2);
    local messageMode = tvb:range(31, 1);
    local messageText = tvb:range(32, 32);
    local fix = tvb:range(64, 1);
    local latitude = tvb:range(65, 4);
    local longitude = tvb:range(69, 4);

    root_tree:add_le(infobip_datetime, dataora);
    root_tree:add(infobip_applMode, applmode);
    root_tree:add(infobip_applStatus, applStatus);
    root_tree:add(infobip_serviceStatus, serviceStatus);
    root_tree:add(infobip_cnvTotal, cnvTotal);
    root_tree:add(infobip_cnvServiceCount, cnvServiceCount);
    root_tree:add(infobip_cnvStatus, cnvStatus);
    root_tree:add(infobip_localityType, localityType);
    root_tree:add(infobip_localityValue, localityValue);
    root_tree:add(infobip_messageMode, messageMode);
    root_tree:add(infobip_messageText, messageText);
    root_tree:add(infobip_fix, fix);
    root_tree:add_le(infobip_latitude, latitude);
    root_tree:add_le(infobip_longitude, longitude);

    return true;
end

local function dissectINFOBIP2(tvb, pinfo, root_tree)

    print("enter function dissectINFOBIP2");

    dissectINFOBIP1(tvb, pinfo, root_tree);

    pinfo.cols.info = "infonet-INFO_BIP2";

    local gpsSignalLevel = tvb:range(73, 1);
    local gprsSignalLevel = tvb:range(74, 1);
    local wiFiSignalLevel = tvb:range(75, 1);
    local ipLinkStatus = tvb:range(76, 1);
    local localityCodeBip = tvb:range(77, 1);
    local localityDescriptionBip = tvb:range(81, 41);
    local lineCodeBip = tvb:range(122, 4);
    local lineDescriptionBip = tvb:range(126, 41);

    root_tree:add(infobip_gpsSignalLevel, gpsSignalLevel);
    root_tree:add(infobip_gprsSignalLevel, gprsSignalLevel);
    root_tree:add(infobip_wiFiSignalLevel, wiFiSignalLevel);
    root_tree:add(infobip_ipLinkStatus, ipLinkStatus);
    root_tree:add(infobip_localityCodeBip, localityCodeBip);
    root_tree:add(infobip_localityDescriptionBip, localityDescriptionBip);
    root_tree:add_le(infobip_lineCodeBip, lineCodeBip);
    root_tree:add(infobip_lineDescriptionBip, lineDescriptionBip);

    return true;
end

local subdissectors = {
    INFO_NET2 = dissectINFONET2,
    INFO_NET = dissectINFONET2,
    INFO_BIP = dissectINFOBIP1,
    INFO_BIP2 = dissectINFOBIP2

}

local function ValidatePacket(buffer, pinfo)

    local length = tonumber(buffer:len());
    print("buffer length: " .. length);

    if length > 167 then
        print("LEN PACKET WRONG");
        return false;
    end

    local header = buffer(1, 10):stringz();
    print("header: " .. header);

    if subdissectors[header] == nil then
        print("subdissector: FALSE");
        return false;
    end
    if pinfo.dst_port ~= pred_port then
        print("DEST_PORT: FALSE");
        return false;
    end
    if header == "INFO_NET2" and length ~= 101 then
        print("LEN INFO_NET2: FALSE");
        return false;
    end
    if header == "INFO_BIP" and length ~= 73 then
        print("LEN INFO_BIP: FALSE");
        return false;
    end
    if header == "INFO_BIP2" and length ~= 167 then
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

function infonet.dissector(buffer, pinfo, tree)

    if ValidatePacket(buffer, pinfo) == false then
        print("PACKET NOT VALID");
        return false;
    end

    local header = buffer(1, 10):stringz();
    pinfo.cols.protocol = "infonet." .. header:lower();

    if header == "INFO_NET2" or header == "INFO_NET" then
        infonet = infonet2;
    end
    if header == "INFO_BIP" or header == "INFO_BIP" then
        infonet = infobip;
    end

    local subtree = tree:add(infonet, buffer(), "infonet (" .. header .. ") Packet Length " .. buffer:len());
    return subdissectors[header](buffer, pinfo, subtree);
end

local udp_encap_table = DissectorTable.get("udp.port");
udp_encap_table:add(infonet.prefs.pred_port, infonet);
