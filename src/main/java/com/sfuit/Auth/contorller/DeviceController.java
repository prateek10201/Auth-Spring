package com.sfuit.Auth.contorller;

import com.sfuit.Auth.entity.Devices;
import com.sfuit.Auth.services.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/users")
public class DeviceController {

    @Autowired
    DeviceService deviceService;


    @PostMapping("/verifyDevice")
    public ResponseEntity<Map<String, String>> verifyDevice(@RequestBody Map<String, Object> userMap)
    {
        String device_id = (String) userMap.get("device_id");
        Devices devices = deviceService.deviceIdAvailable(device_id);
        return new ResponseEntity<>(checkDeviceValidity(devices), HttpStatus.OK);
    }


    @PostMapping("/addDevice")
    public ResponseEntity<Map<String, String>> registerDevice(@RequestBody Map<String, Object> userMap)
    {
        String device_id = (String) userMap.get("device_id");
        String sensors = (String) userMap.get("sensors");
        String device_isverified = "false";

        Devices devices = deviceService.addDevice(device_id, sensors, device_isverified);
        return new ResponseEntity<>(generateDeviceDefault(devices), HttpStatus.OK);
    }

    private Map<String, String> generateDeviceDefault(Devices devices)
    {
        Map<String , String> map = new HashMap<>();
        map.put("device_id",devices.getDevice_id());
        map.put("sensors",devices.getSensors());
        map.put("device_isverified",devices.getDevice_isverified());
        return map;
    }

    private Map<String, String> checkDeviceValidity(Devices devices) {
        Map<String , String> map = new HashMap<>();
        map.put("device_id",devices.getDevice_id());
        return map;
    }

}
