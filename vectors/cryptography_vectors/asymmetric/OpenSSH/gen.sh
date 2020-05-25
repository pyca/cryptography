#! /bin/sh

rm *.key *.pub

# avoid having too many files
ecbits="ecbits.txt"
echo 521 > "$ecbits"
getecbits() {
    last=$(cat $ecbits)
    case "$last" in
    256) last=384;;
    384) last=521;;
    521) last=256;;
    esac
    echo $last > "$ecbits"
    echo $last
}

genkey() {
    fn="$1"
    args="-f $fn -C $fn"
    case "$fn" in
    ecdsa-*) args="$args -t ecdsa -b $(getecbits)" ;;
    rsa-*) args="$args -t rsa" ;;
    dsa-*) args="$args -t dsa" ;;
    ed25519-*) args="$args -t ed25519" ;;
    esac
    password=''
    case "$fn" in
    *-psw.*) password="password" ;;
    esac
    ssh-keygen -q -o $args -N "$password"
}

# generate private key files
for ktype in rsa dsa ecdsa ed25519; do
    for psw in nopsw psw; do
        genkey "${ktype}-${psw}.key"
    done
done

# generate public key files
for fn in *.key; do
  ssh-keygen -q -y -f "$fn" > /dev/null
done

rm -f "$ecbits"

# generate public key files with certificate
ssh-keygen -q -s "dsa-nopsw.key" -I "name" \
    -z 1 -V 20100101123000:21090101123000 \
    "dsa-nopsw.key.pub"
ssh-keygen -q -s "rsa-nopsw.key" -I "name" \
    -z 2 -n user1,user2 -t rsa-sha2-512 \
    "rsa-nopsw.key.pub"
ssh-keygen -q -s "ecdsa-nopsw.key" -I "name" \
    -h -n domain1,domain2 \
    "ecdsa-nopsw.key.pub"
ssh-keygen -q -s "ed25519-nopsw.key" -I "name" \
    -O no-port-forwarding \
    "ed25519-nopsw.key.pub"

