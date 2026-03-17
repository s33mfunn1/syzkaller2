# Покрытие (coverage) для gtp.c
# KCOV: включить CONFIG_KCOV=y, использовать KCOV_REMOTE_ENABLE с common_handle
#       для сбора покрытия при фаззинге GTP-пакетов

# Включить debug для GTP
echo 'file drivers/net/gtp.c +p' > /sys/kernel/debug/dynamic_debug/control

ip link add gtp0 type gtp role ggsn
ip addr add 192.168.60.1/24 dev gtp0
ip link set gtp0 up

# on host machine
scp -i $IMAGE/trixie.id_rsa -P 10021 ./debug_programs/gtp_tap_inject.c root@localhost:/root


gcc -o gtp_tap_inject gtp_tap_inject.c
./gtp_tap_inject 192.168.60.1
