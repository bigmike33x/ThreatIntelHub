#!/usr/bin/env python3
"""
add_gang_attribution.py
=======================
One-time migration + ongoing utility for ransomware gang attribution.

What it does:
  1. Adds gang_name + gang_confidence columns to the sites table (safe to re-run)
  2. Backfills known hosts from RANSOMWARE_GANG_MAP  (confidence = 'seed')
  3. Runs content fingerprinting on remaining Ransomware-category rows (confidence = 'fingerprint')
  4. Prints a summary of coverage

Run:
    python add_gang_attribution.py [--db ~/dark-crawler/crawler.db] [--dry-run]
"""

import sqlite3
import argparse
from pathlib import Path

# ── 1. SEED MAP ───────────────────────────────────────────────────────────────
# hostname → gang name
# Sources: deepdarkCTI ransomware_gang.md + RansomLook.io (May 2026)
# Confidence level for all entries: "seed" (verified/curated)

RANSOMWARE_GANG_MAP: dict[str, str] = {

    # ── LockBit ──────────────────────────────────────────────────────────────
    "lockbitapyum2wks2lbcnrovcgxj7ne3ua7hhcmshh3s3ajtpookohqd.onion":  "LockBit",
    "lockbit23xxhej7swdop24cru7ks2w66pw7zgdkydqo6f7wfyfqo7oqd.onion":  "LockBit",
    "lockbitapp24bvbi43n3qmtfcasf2veaeagjxatgbwtxnsh5w32mljad.onion":  "LockBit",
    "lockbit3g3ohd3katajf6zaehxz4h4cnhmz5t735zpltywhwpc6oy3id.onion":  "LockBit",
    "lockbit3olp7oetlc4tl5zydnoluphh7fvdt5oa6arcp2757r7xkutid.onion":  "LockBit",
    "lockbit3753ekiocyo5epmpy6klmejchjtzddoekjlnt6mu3qh4de2id.onion":  "LockBit",
    "lockbitapt2yfbt7lchxejug47kmqvqqxvvjpqkmevv4l3azl3gy6pyd.onion":  "LockBit",
    "lockbitapt2d73krlbewgv27tquljgxr33xbwwsp6rkyieto7u4ncead.onion":  "LockBit",
    "lockbitapt34kvrip6xojylohhxrwsvpzdffgs5z4pbbsywnzsbdguqd.onion":  "LockBit",
    "lockbitapt5x4zkjbcqmz6frdhecqqgadevyiwqxukksspnlidyvd7qd.onion":  "LockBit",
    "lockbitapt67g6rwzjbcxnww5efpg4qok6vpfeth7wx3okj52ks4wtad.onion":  "LockBit",
    "lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion":  "LockBit",
    "lockbitapt72iw55njgnqpymggskg5yp75ry7rirtdg4m7i42artsbqd.onion":  "LockBit",
    "lockbitaptawjl6udhpd323uehekiyatj6ftcxmkwe5sezs4fqgpjpid.onion":  "LockBit",
    "lockbitaptbdiajqtplcrigzgdjprwugkkut63nbvy2d5r4w2agyekqd.onion":  "LockBit",
    "lockbitapiahy43zttdhslabjvx4q6k24xx7r33qtcvwqehmnnqxy3yd.onion":  "LockBit",
    "lockbitapo3wkqddx2ka7t45hejurybzzjpos4cpeliudgv35kkizrid.onion":  "LockBit",
    "lockbiti7ss2wzyizvyr2x46krnezl4xjeianvupnvazhbqtz32auqqd.onion":  "LockBit",
    "lockbit7ouvrsdgtojeoj5hvu6bljqtghitekwpdy3b6y62ixtsu5jqd.onion":  "LockBit",
    "lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd.onion":  "LockBit",
    "lockbit7ixelt7gn3ynrs3dgqtsom6x6sd2ope4di7bu6e6exyhazeyd.onion":  "LockBit",
    "lockbitw2ygzasbt35ffpdb46r4vkej6flm3siyabaxzdodwpiatfgqd.onion":  "LockBit",
    "lockbitck6escin3p33v3f5uef3mr5fx335oyqon2uqoyxuraieuhiqd.onion":  "LockBit",
    "lockbitcuo23q7qrymbk6dsp2sadltspjvjxgcyp4elbnbr6tcnwq7qd.onion":  "LockBit",
    "lockbitfile2tcudkcqqt2ve6btssyvqwlizbpv5vz337lslmhff2uad.onion":  "LockBit",
    "lockbitfhzimjqx2v7p2vfu57fpdm5zh2vsbfk5jkjod3k5pszbek7ad.onion":  "LockBit",
    "lockbitqfj7mmhrfa7lznj47ogknqanskj7hyk2vistn2ju5ufrhbpyd.onion":  "LockBit",
    "lockbitnotexk2vnf2q2zwjefsl3hjsnk4u74vq4chxrqpjclfydk4ad.onion":  "LockBit",
    "lockbitkwkmhfb2zr3ngduaa6sd6munslzkbtqhn5ifmwqml4sl7znad.onion":  "LockBit",
    "lockbitsup4yezcd5enk5unncx3zcy7kw6wllyqmiyhvanjj352jayid.onion":  "LockBit",
    "lockbitsuppyx2jegaoyiw44ica5vdho63m5ijjlmfb7omq3tfr3qhyd.onion":  "LockBit",
    "lockbit4lahhluquhoka3t4spqym2m3dhe66d6lr337glmnlgg2nndad.onion":  "LockBit",
    "lockbit435xk3ki62yun7z5nhwz6jyjdp2c64j5vge536if2eny3gtid.onion":  "LockBit",
    "lockbit33chewwx25efq6dgkhkw4u7nefudq4ijkuamjfd7x73on6dyd.onion":  "LockBit",
    "lockbit6knrauo3qafoksvl742vieqbujxw7rd6ofzdtapjb4rrawqad.onion":  "LockBit",
    "lockbitapyx2kr5b7ma7qn6ziwqgbrij2czhcbojuxmgnwpkgv2yx2yd.onion":  "LockBit",

    # ── ALPHV / BlackCat ──────────────────────────────────────────────────────
    "alphvuzxyxv6ylumd2ngp46xzq3pw6zflomrghvxeuks6kklberrbmyd.onion":  "ALPHV/BlackCat",

    # ── Akira ─────────────────────────────────────────────────────────────────
    "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion":  "Akira",

    # ── CICADA3301 ────────────────────────────────────────────────────────────
    "cicadabv7vicyvgz5khl7v2x5yygcgow7ryy6yppwmxii4eoobdaztqd.onion":  "CICADA3301",

    # ── Qilin (aka Agenda) — #1 active gang May 2026, source: RansomLook ─────
    "ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion":  "Qilin",
    "pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd.onion":  "Qilin",
    "kbsqoivihgdmwczmxkbovk7ss2dcynitwhhfu5yw725dboqo5kthfaad.onion":  "Qilin",
    "24kckepr3tdbcomkimbov5nqv2alos6vmrmlxdr76lfmkgegukubctyd.onion":  "Qilin",
    "kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad.onion":  "Qilin",

    # ── DragonForce — cartel RaaS, behind M&S/Harrods/Co-op attacks ──────────
    "z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion":  "DragonForce",
    "dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd.onion":  "DragonForce",
    "fsguestuctexqqaoxuahuydfa6ovxuhtng66pgyr5gqcrsi7qgchpkad.onion":  "DragonForce",
    "3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion":  "DragonForce",

    # ── Rhysida ───────────────────────────────────────────────────────────────
    "rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion":  "Rhysida",
    "rhysidafc6lm7qa2mkiukbezh7zuth3i4wof4mh2audkymscjm6yegad.onion":  "Rhysida",

    # ── Hunters International ─────────────────────────────────────────────────
    "hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd.onion":  "Hunters International",
    "hunters33mmcwww7ek7q5ndahul6nmzmrsumfs6aenicbqon6mxfiqyd.onion":  "Hunters International",
    "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion":  "Hunters International",

    # ── NoEscape ──────────────────────────────────────────────────────────────
    "noescaperjh3gg6oy7rck57fiefyuzmj7kmvojxgvlmwd5pdzizrb7ad.onion":  "NoEscape",
    "noescapemsqxvizdxyl7f7rmg5cdjwp33pg2wpmiaaibilb4btwzttad.onion":  "NoEscape",

    # ── AvosLocker ────────────────────────────────────────────────────────────
    "avosqxh72b5ia23dl5fgwcpndkctuzqvh2iefk5imp3pi5gfhel5klad.onion":  "AvosLocker",
    "avosjon4pfh3y7ew3jdwz6ofw7lljcxlbk7hcxxmnxlh5kvf2akcqjad.onion":  "AvosLocker",

    # ── Cuba ──────────────────────────────────────────────────────────────────
    "cuba4ikm4jakjgmkezytyawtdgr2xymvy6nvzgw5cglswg3si76icnqd.onion":  "Cuba",

    # ── Royal ─────────────────────────────────────────────────────────────────
    "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion":  "Royal",

    # ── Black Basta ───────────────────────────────────────────────────────────
    "black3gnkizshuynieigw6ejgpblb53mpasftzd6pydqpmq2vn2xf6yd.onion":  "Black Basta",

    # ── Medusa ────────────────────────────────────────────────────────────────
    "medusaxko7jxtrojdkxo66j7ck4q5tgktf7uqsqyfry4ebnxlcbkccyd.onion":  "Medusa",

    # ── Play ──────────────────────────────────────────────────────────────────
    "omx5iqrdbsoitf3q4xexrqw5r5tfw7vp3vl3li3lfo7saabxazshnead.onion":  "Play",

    # ── Cl0p ──────────────────────────────────────────────────────────────────
    "santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion":  "Cl0p",

    # ── RansomHub ─────────────────────────────────────────────────────────────
    "ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion":  "RansomHub",
    "ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion":  "RansomHub",
    "ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion":  "RansomHub",

    # ── INC Ransom ────────────────────────────────────────────────────────────
    "incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion":  "INC Ransom",
    "incblog7vmuq7rktic73r4ha4j757m3ptym37tyvifzp2roedyyzzxid.onion":  "INC Ransom",

    # ── Lorenz ────────────────────────────────────────────────────────────────
    "lorenzmlwpzgxq736jzseuterytjueszsvznuibanxomlpkyxk6ksoyd.onion":  "Lorenz",

    # ── LunaLock ─────────────────────────────────────────────────────────────
    "lunalockcccxzkpfovwzifwxcytqkiuak6wzybnniqwxcmpsetpbetid.onion":  "LunaLock",

    # ── BianLian ─────────────────────────────────────────────────────────────
    "bianlivemqbawcco4cx4a672k2fip3guyxudzurfqvdszafam3ofqgqd.onion":  "BianLian",
    "bianlianlbc5an4kgnay3opdemgcryg2kpfcbgczopmm3dnbz3uaunad.onion":  "BianLian",
    "bianliaoxoeriowgqohcly4a6sbkpc3se2yvxgidxomxlpuhx5ehrpad.onion":  "BianLian",

    # ── Sarcoma ───────────────────────────────────────────────────────────────
    "sarcomawmawlhov7o5mdhz4eszxxlkyaoiyiy2b5iwxnds2dmb4jakad.onion":  "Sarcoma",

    # ── Nitrogen ─────────────────────────────────────────────────────────────
    "nitrogenczslprh3xyw6lh5xyjvmsz7ciljoqxxknd7uymkfetfhgvqd.onion":  "Nitrogen",

    # ── Vector ───────────────────────────────────────────────────────────────
    "vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd.onion":  "Vector",

    # ── Cactus ───────────────────────────────────────────────────────────────
    "cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion":  "Cactus",

    # ── Embargo ───────────────────────────────────────────────────────────────
    "embargobe3n5okxyzqphpmk3moinoap2snz5k6765mvtkk7hhi544jid.onion":  "Embargo",

    # ── FunkSec ───────────────────────────────────────────────────────────────
    "funksecsekgasgjqlzzkmcnutrrrafavpszijoilbd6z3dkbzvqu43id.onion":  "FunkSec",
    "funkxxkovrk7ctnggbjnthdajav4ggex53k6m2x3esjwlxrkb3qiztid.onion":  "FunkSec",

    # ── Sicari ───────────────────────────────────────────────────────────────
    "sicarilxx2br6esqnhad4w26bcgb5j2snbbnhyo4b6t7kby2oy4x3jad.onion":  "Sicari",
    "sicariktdbhjtrk6f2pwdh6wlequw7pcjva25skkzz4m3zz3opyox3qd.onion":  "Sicari",
    "sicarinb4ktqcdpubjifzw3vixvzgtwacjmc5ks56kev52gxitegigad.onion":  "Sicari",
    "sicari7m63wlggfxajiuonfsk72fgencne5ztzakyuhfxzq5rnbkjead.onion":  "Sicari",
    "sicariifoucvhyqg54smi3esg5sfcyw5z65t6yigqu4loyuoz62bb2id.onion":  "Sicari",
    "sicari7zpu3mtxqggde7mu3ywppntdqg22arcukvlaihjbfcb2rnktid.onion":  "Sicari",

    # ── Sinobi ───────────────────────────────────────────────────────────────
    "sinobi7l3wet3uqn4cagjiessuomv75aw3bvgah4jpj43od7xndb7kad.onion":  "Sinobi",
    "sinobi7sukclb3ygtorysbtrodgdbnrmgbhov45rwzipubbzhiu5jvqd.onion":  "Sinobi",
    "sinobi6ftrg27d6g4sjdt65malds6cfptlnjyw52rskakqjda6uvb7yd.onion":  "Sinobi",
    "sinobi23i75c3znmqqxxyuzqvhxnjsar7actgvc4nqeuhgcn5yvz3zqd.onion":  "Sinobi",
    "sinobi6ywgmmvg2gj2yygkb2hxbimaxpqkyk27wti5zjwhfcldhackid.onion":  "Sinobi",
    "sinobi6rlec6f2bgn6rd72xo7hvds4a5ajiu2if4oub2sut7fg3gomqd.onion":  "Sinobi",
    "sinobia6mw6ht2wcdjphessyzpy7ph2y4dyqbd74bgobgju4ybytmkqd.onion":  "Sinobi",

    # ── LynxLocker ───────────────────────────────────────────────────────────
    "lynxblogxutufossaeawlij3j3uikaloll5ko6grzhkwdclrjngrfoid.onion":  "LynxLocker",
    "lynxblogxstgzsarfyk2pvhdv45igghb4zmthnzmsipzeoduruz3xwqd.onion":  "LynxLocker",
    "lynxblogco7r37jt7p5wrmfxzqze7ghxw6rihzkqc455qluacwotciyd.onion":  "LynxLocker",
    "lynxblogijy4jfoblgix2klxmkbgee4leoeuge7qt4fpfkj4zbi2sjyd.onion":  "LynxLocker",
    "lynxblogmx3rbiwg3rpj4nds25hjsnrwkpxt5gaznetfikz4gz2csyad.onion":  "LynxLocker",
    "lynxblogoxllth4b46cfwlop5pfj4s7dyv37yuy7qn2ftan6gd72hsad.onion":  "LynxLocker",
    "lynxblogtwatfsrwj3oatpejwxk5bngqcd5f7s26iskagfu7ouaomjad.onion":  "LynxLocker",

    # ── VanHel ────────────────────────────────────────────────────────────────
    "vanhelwmbf2bwzw7gmseg36qqm4ekc5uuhqbsew4eihzcahyq7sukzad.onion":  "VanHel",
    "vanhelqmjstkvlhrjwzgjzpq422iku6wlggiz5y5r3rmfdeiaj3ljaid.onion":  "VanHel",
    "vanhelxjo52qr2ixcmtjayqqrcodkuh36n7uq7q7xj23ggotyr3y72yd.onion":  "VanHel",
    "vanhelvuuo4k3xsiq626zkqvp6kobc2abry5wowxqysibmqs5yjh4uqd.onion":  "VanHel",

    # ── BravoNormal ───────────────────────────────────────────────────────────
    "bravoxxtrmqeeevhl7gdh2yzvlrjxajr66d33c7ozosrccx4cz7cepad.onion":  "BravoNormal",
    "bravoxxwcfz5qk43ychgveprpd5mw5hvxfs4a2uz2okx7mumiht4fzyd.onion":  "BravoNormal",

    # ── Bashe ────────────────────────────────────────────────────────────────
    "basherq53eniermxovo3bkduw5qqq5bkqcml3qictfmamgvmzovykyqd.onion":  "Bashe",
    "bashete63b3gcijfofpw6fmn3rwnmyi5aclp55n6awcfbexivexbhyad.onion":  "Bashe",
    "basherykagbxoaiaxkgqhmhd5gbmedwb3di4ig3ouovziagosv4n77qd.onion":  "Bashe",
    "basheqtvzqwz4vp6ks5lm2ocq7i6tozqgf6vjcasj4ezmsy4bkpshhyd.onion":  "Bashe",
    "bashex7mokreyoxl6wlswxl4foi7okgs7or7aergnuiockuoq35yt3ad.onion":  "Bashe",

    # ── Nova ─────────────────────────────────────────────────────────────────
    "novadmrkp4vbk2padk5t6pbxolndceuc7hrcq4mjaoyed6nxsqiuzyyd.onion":  "Nova",
    "novaxtychr6ohlc4zr5its73p6i7unpuhpwoodtzrg2y4w4seytatlid.onion":  "Nova",
    "novag4k2te3mstt2xq5irywlpaw6edgkpiwgg4t2q7eecisj2qqtvbid.onion":  "Nova",
    "novatd4577pzlvdyy42slydhrhru7fpcflbbxlajcmbfrgzyeis6d3id.onion":  "Nova",
    "novaoddh3vxylxqpsfdjprliknbzgbkv6nkazpzu3cvykrgpyzuywryd.onion":  "Nova",
    "novazzitmugtbjwuttc5hhsemkmvwh3iyt27oeeunu5mkw62qpfeykid.onion":  "Nova",

    # ── ThreeAM ───────────────────────────────────────────────────────────────
    "threeamkelxicjsaf2czjyz2lc4q3ngqkxhhlexyfcp2o6raw4rphyad.onion":  "ThreeAM",

    # ── Onyx ─────────────────────────────────────────────────────────────────
    "onyxcym4mjilrsptk5uo2dhesbwntuban55mvww2olk5ygqafhu3i3yd.onion":  "Onyx",

    # ── Stormous ─────────────────────────────────────────────────────────────
    "stmxylixiz4atpmkspvhkym4xccjvpcv3v67uh3dze7xwwhtnz4faxid.onion":  "Stormous",

    # ── Brain Cipher — hit Indonesia national data center ─────────────────────
    "nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad.onion":  "Brain Cipher",

    # ── Daixin Team — healthcare-focused, FBI/CISA advisory ───────────────────
    "ijbw7iiyodqzpg6ooewbgn6mv2pinoer3k5pzdecoejsw5nyoe73zvad.onion":  "Daixin",

    # ── Abyss-Data (Abyss Locker) — ESXi-focused, Babuk-derived ──────────────
    "6oeuvb4fq65xlrft2ezxjmkeqnu7oafbsevrr3ocer27wft6ivvhstqd.onion":  "Abyss-Data",

    # ── BlackByte ────────────────────────────────────────────────────────────
    "vqifktlreqpudvulhbzmc5gocbeawl67uvs2pttswemdorbnhaddohyd.onion":  "BlackByte",

    # ── KryBit ───────────────────────────────────────────────────────────────
    "kryptospnjzz7vfkr663bnqv3dxirmr3svo5zwq7cvu2wdfngujgknyd.onion":  "Krypto",
    "krybitqsdzwmhnitvwuhvsntfgf2wrhxveyxroxpc44c6gkft2cqldyd.onion":  "KryBit",
    "krybitxdpxohsmjooeb3gbgpmdddreh6mnflzac6bnezz74b7yje67yd.onion":  "KryBit",
    "krybitx3fh5krdnhegyp2ob3lhizsaiadturtio3ginf7it5gsdgu2yd.onion":  "KryBit",

    # ── KillSec ──────────────────────────────────────────────────────────────
    "kill432ltnkqvaqntbalnsgojqqs2wz4lhnamrqjg66tq6fuvcztilyd.onion":  "KillSec",

    # ── Knight ───────────────────────────────────────────────────────────────
    "knight3xppu263m7g4ag3xlit2qxpryjwueobh7vjdc3zrscqlfu3pqd.onion":  "Knight",

    # ── Quantum ──────────────────────────────────────────────────────────────
    "quantum445bh3gzuyilxdzs5xdepf3b7lkcupswvkryf3n7hgzpxebid.onion":  "Quantum",

    # ── Flock ────────────────────────────────────────────────────────────────
    "flock4cvoeqm4c62gyohvmncx6ck2e7ugvyqgyxqtrumklhd5ptwzpqd.onion":  "Flock",

    # ── Beast ────────────────────────────────────────────────────────────────
    "beast6azu4f7fxjakiayhnssybibsgjnmy77a6duufqw5afjzfjhzuqd.onion":  "Beast",

    # ── Cloak ────────────────────────────────────────────────────────────────
    "cloak7jpvcb73rtx2ff7kaw2kholu7bdiivxpzbhlny4ybz75dpxckqd.onion":  "Cloak",

    # ── CiphBit ──────────────────────────────────────────────────────────────
    "ciphbitqyg26jor7eeo6xieyq7reouctefrompp6ogvhqjba7uo4xdid.onion":  "CiphBit",

    # ── Cryogenics / CryoBlog ─────────────────────────────────────────────────
    "cryoblogedawivdcknyd4jsjxkrx3xrqqltxla6wwjjnzm3f3jaxjzqd.onion":  "Cryogenics",

    # ── Termite ──────────────────────────────────────────────────────────────
    "termiteuslbumdge2zmfmfcsrvmvsfe4gvyudc5j6cdnisnhtftvokid.onion":  "Termite",

    # ── DireWolf ─────────────────────────────────────────────────────────────
    "direwolfcdkv5whaz2spehizdg22jsuf5aeje4asmetpbt6ri4jnd4qd.onion":  "DireWolf",

    # ── SafePay ──────────────────────────────────────────────────────────────
    "safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd.onion":  "SafePay",

    # ── Meow ─────────────────────────────────────────────────────────────────
    "meow6xanhzfci2gbkn3lmbqq7xjjufskkdfocqdngt3ltvzgqpsg5mid.onion":  "Meow",

    # ── APT73 ────────────────────────────────────────────────────────────────
    "apt73grpjgjwykrenq7vnjejue76vosdzptdvmonv7vyqnsyokrw57ad.onion":  "APT73",

    # ── Broherhood ───────────────────────────────────────────────────────────
    "brohoodyaifh2ptccph5zfljyajjabwjjo4lg6gfp4xb6ynw5w7ml6id.onion":  "Broherhood",

    # ── Netrunner ────────────────────────────────────────────────────────────
    "netrunrsb3bivj5gnwajzxlig5qkteb6edgthxj7fmsvhkzxtwfxwaad.onion":  "Netrunner",

    # ── Trident ──────────────────────────────────────────────────────────────
    "tridentfrdy6jydwywfx4vx422vnto7pktao2gyx2qdcwjanogq454ad.onion":  "Trident",

    # ── OmegaLock ────────────────────────────────────────────────────────────
    "omegalock5zxwbhswbisc42o2q2i54vdulyvtqqbudqousisjgc7j7yd.onion":  "OmegaLock",

    # ── Osirus ───────────────────────────────────────────────────────────────
    "osirisbm3357xrccnid23nlyuqwzbgqheaei6dxvyi34tbkqr3bmvfid.onion":  "Osirus",

    # ── Obscura ──────────────────────────────────────────────────────────────
    "obscurad3aphckihv7wptdxvdnl5emma6t3vikcf3c5oiiqndq6y6xad.onion":  "Obscura",

    # ── Orca ─────────────────────────────────────────────────────────────────
    "orca66hwnpciepupe5626k2ib6dds6zizjwuuashz67usjps2wehz4id.onion":  "Orca",

    # ── NoName ───────────────────────────────────────────────────────────────
    "noname2j6zkgnt7ftxsjju5tfd3s45s4i3egq5bqtl72kgum4ldc6qyd.onion":  "NoName",

    # ── World Leaks ──────────────────────────────────────────────────────────
    "worldleaksartrjm3c6vasllvgacbi5u3mgzkluehrzhk2jz4taufuid.onion":  "World Leaks",

    # ── NokoLeaks ────────────────────────────────────────────────────────────
    "nokoleakb76znymx443veg4n6fytx6spck6pc7nkr4dvfuygpub6jsid.onion":  "NokoLeaks",

    # ── RaWorld ──────────────────────────────────────────────────────────────
    "raworldw32b2qxevn3gp63pvibgixr4v75z62etlptg3u3pmajwra4ad.onion":  "RaWorld",

    # ── BlackSuit (Royal rebrand) ─────────────────────────────────────────────
    "aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion":  "BlackSuit",

    # ── Vice Society ─────────────────────────────────────────────────────────
    "vsociethok6sbprvevl4dlwbqrzyhxcxaqpvcqt5belwvsuxaxsutyad.onion":  "Vice Society",
}


# ── 2. CONTENT FINGERPRINTS ───────────────────────────────────────────────────
# Used for sites NOT in the seed map.
# Match against lowercased title + preview text.
# Sources: deepdarkCTI + RansomLook.io (May 2026)

GANG_FINGERPRINTS: dict[str, list[str]] = {
    # Established groups
    "LockBit":               ["lockbit", "lb3", "lb2", "lockbit 3", "lockbit2"],
    "ALPHV/BlackCat":        ["alphv", "blackcat", "black cat ransomware"],
    "Akira":                 ["akira ransomware", "akira team", "akirateam"],
    "Cl0p":                  ["cl0p", "clop ransomware", "ta505"],
    "Black Basta":           ["black basta", "blackbasta"],
    "CICADA3301":            ["cicada3301", "cicada 3301"],
    "RansomHub":             ["ransomhub", "ransom hub"],
    "Medusa":                ["medusalocker", "medusa blog", "medusa ransomware"],
    "Play":                  ["play ransomware", "playransomware", "play inc"],
    "Royal":                 ["royal ransomware", "royal group"],
    "Rhysida":               ["rhysida"],
    "Hunters International": ["hunters international", "hunterint"],
    "BianLian":              ["bianlian", "bian lian"],
    "NoEscape":              ["noescape", "no escape ransomware"],
    "Cactus":                ["cactus ransomware", "cactus gang", "cactus.readme"],
    "INC Ransom":            ["inc ransom", "incransom", "inc blog"],
    "Embargo":               ["embargo ransomware"],
    "Cuba":                  ["cuba ransomware", "cuba team"],
    "AvosLocker":            ["avoslocker", "avos locker"],
    "FunkSec":               ["funksec", "funk sec"],
    "Lorenz":                ["lorenz ransomware", "lorenz team"],
    "Nitrogen":              ["nitrogen ransomware", "nitrogen blog"],
    "KillSec":               ["killsec", "kill sec"],
    "Termite":               ["termite ransomware"],
    "SafePay":               ["safepay ransomware", "safe pay ransomware"],
    "DireWolf":              ["direwolf", "dire wolf ransomware"],
    "Cloak":                 ["cloak ransomware"],
    "ThreeAM":               ["3am ransomware", "threeam", "three am"],
    "Sarcoma":               ["sarcoma ransomware", "sarcoma group"],
    "VanHel":                ["vanhel", "van hel ransomware"],
    "LynxLocker":            ["lynxlocker", "lynx ransomware", "lynxblog"],
    "LunaLock":              ["lunalock", "luna lock"],
    "Beast":                 ["beast ransomware"],
    "CiphBit":               ["ciphbit", "ciph bit"],
    "Quantum":               ["quantum locker", "quantum ransomware"],
    "APT73":                 ["apt73", "apt 73"],
    "Broherhood":            ["broherhood ransomware"],
    "Vice Society":          ["vice society", "vicesociety"],
    "BlackSuit":             ["blacksuit", "black suit ransomware"],
    "NoName":                ["noname ransomware blog"],
    "World Leaks":           ["world leaks", "worldleaks"],
    "Knight":                ["knight ransomware"],
    "Flock":                 ["flock ransomware"],
    "OmegaLock":             ["omega lock", "omegalocker"],
    "RaWorld":               ["raworld", "ra world ransomware"],
    "BlackByte":             ["blackbyte", "black byte ransomware", "blackbyte2"],
    "Abyss-Data":            ["abyss locker", "abyss-data", "abyssdata"],
    "Brain Cipher":          ["brain cipher", "braincipher"],
    "Daixin":                ["daixin", "daixin team"],
    "Dark Angels":           ["dark angels ransomware", "darkangels", "dunghill leak"],
    "8Base":                 ["8base", "8 base ransomware"],
    "Dark Power":            ["dark power ransomware", ".dark_power"],
    "Blackout":              ["blackout ransomware", "blackout group"],
    "Brotherhood":           ["brotherhood ransomware"],

    # Active groups from RansomLook May 2026
    "Qilin":                 ["qilin ransomware", "agenda ransomware", "qilin blog",
                              "qilin group", "readme-recover"],
    "DragonForce":           ["dragonforce", "dragon force ransomware",
                              "dragonforce cartel", "dragonforce blog", "dragongo"],
    "LockBit5":              ["lockbit5", "lockbit 5", "lb5 ransomware"],
    "Stormous":              ["stormous", "stormous ransomware", "stormous team"],
    "Nightspire":            ["nightspire", "night spire ransomware"],
    "The Gentlemen":         ["the gentlemen ransomware", "gentlemen ransomware group"],
    "Lamashtu":              ["lamashtu", "lamashtu ransomware"],
    "Bavacai":               ["bavacai", "bavacai ransomware"],
    "Exitium":               ["exitium", "exitium ransomware"],
    "Chaos":                 ["chaos ransomware group", "chaos raas"],
    "Ailock":                ["ailock", "ai lock ransomware", ".ailock"],
    "M3rx":                  ["m3rx", "m3rx ransomware"],
    "Coinbase Cartel":       ["coinbase cartel", "coinbasecartel"],
    "Cmd Organization":      ["cmd organization", "cmd ransomware", "cmd org"],
    "Audit Team":            ["audit team ransomware", "audit entity"],
}


# ── 3. MIGRATION ─────────────────────────────────────────────────────────────

def migrate(db_path: Path, dry_run: bool = False) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Add columns if they don't exist (safe to re-run)
    existing = {row[1] for row in cur.execute("PRAGMA table_info(sites)")}
    for col, typedef in [("gang_name", "TEXT"), ("gang_confidence", "TEXT")]:
        if col not in existing:
            print(f"  Adding column: {col}")
            if not dry_run:
                cur.execute(f"ALTER TABLE sites ADD COLUMN {col} {typedef}")
        else:
            print(f"  Column already exists: {col}")

    # Add index if missing
    if not dry_run:
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_sites_gang "
            "ON sites(gang_name) WHERE gang_name IS NOT NULL"
        )
    conn.commit()

    # ── Pass 1: seed map backfill ─────────────────────────────────────────
    seed_hits = 0
    for hostname, gang in RANSOMWARE_GANG_MAP.items():
        result = cur.execute(
            "SELECT id FROM sites WHERE host = ?", (hostname,)
        ).fetchone()
        if result:
            if not dry_run:
                cur.execute(
                    "UPDATE sites SET gang_name=?, gang_confidence='seed', category='Ransomware' WHERE host=?",
                    (gang, hostname)
                )
            seed_hits += 1

    conn.commit()
    print(f"  Seed map: {seed_hits} sites attributed from {len(RANSOMWARE_GANG_MAP)} known hosts")

    # ── Pass 2: content fingerprinting on unattributed Ransomware sites ───
    unattributed = cur.execute(
        "SELECT id, host, title, preview FROM sites WHERE category='Ransomware' AND gang_name IS NULL"
    ).fetchall()

    fp_hits = 0
    fp_unknown = 0
    for row in unattributed:
        text = f"{row['title'] or ''} {row['preview'] or ''}".lower()
        matched_gang = None
        for gang, keywords in GANG_FINGERPRINTS.items():
            if any(kw in text for kw in keywords):
                matched_gang = gang
                break
        if matched_gang:
            if not dry_run:
                cur.execute(
                    "UPDATE sites SET gang_name=?, gang_confidence='fingerprint' WHERE id=?",
                    (matched_gang, row['id'])
                )
            fp_hits += 1
        else:
            fp_unknown += 1

    conn.commit()

    # ── Summary ───────────────────────────────────────────────────────────
    total_ransomware = cur.execute(
        "SELECT COUNT(*) FROM sites WHERE category='Ransomware'"
    ).fetchone()[0]
    attributed = cur.execute(
        "SELECT COUNT(*) FROM sites WHERE gang_name IS NOT NULL"
    ).fetchone()[0]

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Results:")
    print(f"  Total Ransomware-category sites : {total_ransomware}")
    print(f"  Attributed via seed map         : {seed_hits}")
    print(f"  Attributed via fingerprinting   : {fp_hits}")
    print(f"  Still unknown                   : {fp_unknown}")
    print(f"  Total attributed                : {attributed}")

    # ── Gang breakdown ────────────────────────────────────────────────────
    print("\n  Gang breakdown (top 30):")
    rows = cur.execute(
        "SELECT gang_name, COUNT(*) as n FROM sites WHERE gang_name IS NOT NULL "
        "GROUP BY gang_name ORDER BY n DESC LIMIT 30"
    ).fetchall()
    for r in rows:
        print(f"    {r[0]:<30} {r[1]} site(s)")

    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add gang attribution to ransomware sites in crawler.db")
    parser.add_argument("--db", default="~/dark-crawler/crawler.db", help="Path to crawler.db")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        print(f"ERROR: DB not found at {db_path}")
        exit(1)

    print(f"{'[DRY RUN] ' if args.dry_run else ''}Migrating {db_path} ...")
    migrate(db_path, dry_run=args.dry_run)
    print("\nDone.")
