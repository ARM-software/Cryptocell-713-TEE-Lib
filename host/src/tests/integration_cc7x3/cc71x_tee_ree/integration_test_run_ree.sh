#!/bin/sh
# integration test REE loading script - used by the CPP integration test

drivers_unload() {
    /sbin/depmod
    echo "Unloading any test modules leftovers..."
    /sbin/modprobe -r ccree
    if [[ $? -ne 0 ]]; then echo Failed unloading ccree module.; exit 1; fi
}

drivers_reload() {
   drivers_unload
    /sbin/depmod

    echo "Loading ccree..."
    /sbin/modprobe ccree
    if [[ $? -ne 0 ]]; then echo Failed loading ccree module.; exit 1; fi
    ls /sys/bus/platform/devices/*.arm_ccree/driver > NULL
    if [[ $? -ne 0 ]]; then echo Failed probe of ccree module; exit 1; fi
}


if [ "$1" == "load" ]; then
    # load ree drivers
    drivers_reload

else
    #unload ree driver
    drivers_unload
fi


