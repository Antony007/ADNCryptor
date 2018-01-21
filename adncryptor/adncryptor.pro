#-------------------------------------------------
#
# Project created by QtCreator 2016-12-03T11:29:55
#
#-------------------------------------------------

QT       -= gui

TARGET = adncryptor
TEMPLATE = lib

CONFIG += c++11

DEFINES += ADNCRYPTOR_LIBRARY

SOURCES += adncryptor.cpp \
    qadncryptor.cpp

HEADERS += adncryptor.h \
    cryptpp/cryptlib.h \
    cryptpp/trap.h \
    cryptpp/stdcpp.h \
    cryptpp/config.h \
    cryptpp/aes.h \
    cryptpp/rijndael.h \
    cryptpp/seckey.h \
    cryptpp/secblock.h \
    cryptpp/misc.h \
    cryptpp/simple.h \
    cryptpp/smartptr.h \
    cryptpp/zlib.h \
    cryptpp/zinflate.h \
    cryptpp/zdeflate.h \
    cryptpp/xtrcrypt.h \
    cryptpp/xtr.h \
    cryptpp/words.h \
    cryptpp/winpipes.h \
    cryptpp/whrlpool.h \
    cryptpp/wake.h \
    cryptpp/wait.h \
    cryptpp/vmac.h \
    cryptpp/validate.h \
    cryptpp/twofish.h \
    cryptpp/ttmac.h \
    cryptpp/trunhash.h \
    cryptpp/trdlocal.h \
    cryptpp/tiger.h \
    cryptpp/tea.h \
    cryptpp/strciphr.h \
    cryptpp/square.h \
    cryptpp/sosemanuk.h \
    cryptpp/socketft.h \
    cryptpp/skipjack.h \
    cryptpp/shark.h \
    cryptpp/shacal2.h \
    cryptpp/sha3.h \
    cryptpp/sha.h \
    cryptpp/serpentp.h \
    cryptpp/serpent.h \
    cryptpp/seed.h \
    cryptpp/seal.h \
    cryptpp/salsa.h \
    cryptpp/safer.h \
    cryptpp/rw.h \
    cryptpp/rsa.h \
    cryptpp/rng.h \
    cryptpp/ripemd.h \
    cryptpp/resource.h \
    cryptpp/rdrand.h \
    cryptpp/rc6.h \
    cryptpp/rc5.h \
    cryptpp/rc2.h \
    cryptpp/randpool.h \
    cryptpp/rabin.h \
    cryptpp/queue.h \
    cryptpp/pwdbased.h \
    cryptpp/pubkey.h \
    cryptpp/pssr.h \
    cryptpp/polynomi.h \
    cryptpp/pkcspad.h \
    cryptpp/pch.h \
    cryptpp/panama.h \
    cryptpp/ossig.h \
    cryptpp/osrng.h \
    cryptpp/oids.h \
    cryptpp/oaep.h \
    cryptpp/nr.h \
    cryptpp/network.h \
    cryptpp/nbtheory.h \
    cryptpp/mqv.h \
    cryptpp/mqueue.h \
    cryptpp/modexppc.h \
    cryptpp/modes.h \
    cryptpp/modarith.h \
    cryptpp/mersenne.h \
    cryptpp/mdc.h \
    cryptpp/md5.h \
    cryptpp/md4.h \
    cryptpp/md2.h \
    cryptpp/mars.h \
    cryptpp/luc.h \
    cryptpp/lubyrack.h \
    cryptpp/keccak.h \
    cryptpp/iterhash.h \
    cryptpp/integer.h \
    cryptpp/idea.h \
    cryptpp/ida.h \
    cryptpp/hrtimer.h \
    cryptpp/hmqv.h \
    cryptpp/hmac.h \
    cryptpp/hkdf.h \
    cryptpp/hex.h \
    cryptpp/gzip.h \
    cryptpp/gost.h \
    cryptpp/gfpcrypt.h \
    cryptpp/gf256.h \
    cryptpp/gf2n.h \
    cryptpp/gf2_32.h \
    cryptpp/gcm.h \
    cryptpp/fltrimpl.h \
    cryptpp/fips140.h \
    cryptpp/filters.h \
    cryptpp/files.h \
    cryptpp/fhmqv.h \
    cryptpp/factory.h \
    cryptpp/esign.h \
    cryptpp/eprecomp.h \
    cryptpp/emsa2.h \
    cryptpp/elgamal.h \
    cryptpp/ecp.h \
    cryptpp/eccrypto.h \
    cryptpp/ec2n.h \
    cryptpp/eax.h \
    cryptpp/dsa.h \
    cryptpp/dmac.h \
    cryptpp/dll.h \
    cryptpp/dh2.h \
    cryptpp/dh.h \
    cryptpp/des.h \
    cryptpp/default.h \
    cryptpp/crc.h \
    cryptpp/cpu.h \
    cryptpp/cmac.h \
    cryptpp/channels.h \
    cryptpp/chacha.h \
    cryptpp/ccm.h \
    cryptpp/cbcmac.h \
    cryptpp/cast.h \
    cryptpp/camellia.h \
    cryptpp/blumshub.h \
    cryptpp/blowfish.h \
    cryptpp/blake2.h \
    cryptpp/bench.h \
    cryptpp/basecode.h \
    cryptpp/base64.h \
    cryptpp/base32.h \
    cryptpp/authenc.h \
    cryptpp/asn.h \
    cryptpp/argnames.h \
    cryptpp/arc4.h \
    cryptpp/algparam.h \
    cryptpp/algebra.h \
    cryptpp/adler32.h \
    cryptpp/3way.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../../../Downloads/cryptopp565-build/ -lcryptopp
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../../Downloads/cryptopp565-build/ -lcryptopp

INCLUDEPATH += $$PWD/../../../../Downloads/cryptopp565
DEPENDPATH += $$PWD/../../../../Downloads/cryptopp565
