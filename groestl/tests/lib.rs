#![no_std]

#[macro_use]
extern crate crypto_tests;
extern crate generic_array;
extern crate groestl;

use crypto_tests::hash::{Test, main_test};

#[test]
fn groestl_224_main() {
    let tests = new_tests!(
        "groestl224/0",
        "groestl224/1",
        "groestl224/2",
        "groestl224/3",
        "groestl224/4",
        "groestl224/5",
        "groestl224/6",
        "groestl224/7",
        "groestl224/8",
        "groestl224/9",
        "groestl224/10",
        "groestl224/11",
        "groestl224/12",
        "groestl224/13",
        "groestl224/14",
        "groestl224/15",
        "groestl224/16",
        "groestl224/17",
        "groestl224/18",
        "groestl224/19",
        "groestl224/20",
        "groestl224/21",
        "groestl224/22",
        "groestl224/23",
        "groestl224/24",
        "groestl224/25",
        "groestl224/26",
        "groestl224/27",
        "groestl224/28",
        "groestl224/29",
        "groestl224/30",
        "groestl224/31",
        "groestl224/32",
        "groestl224/33",
        "groestl224/34",
        "groestl224/35",
        "groestl224/36",
        "groestl224/37",
        "groestl224/38",
        "groestl224/39",
        "groestl224/40",
        "groestl224/41",
        "groestl224/42",
        "groestl224/43",
        "groestl224/44",
        "groestl224/45",
        "groestl224/46",
        "groestl224/47",
        "groestl224/48",
        "groestl224/49",
        "groestl224/50",
        "groestl224/51",
        "groestl224/52",
        "groestl224/53",
        "groestl224/54",
        "groestl224/55",
        "groestl224/56",
        "groestl224/57",
        "groestl224/58",
        "groestl224/59",
        "groestl224/60",
        "groestl224/61",
        "groestl224/62",
        "groestl224/63",
        "groestl224/64",
        "groestl224/65",
        "groestl224/66",
        "groestl224/67",
        "groestl224/68",
        "groestl224/69",
        "groestl224/70",
        "groestl224/71",
        "groestl224/72",
        "groestl224/73",
        "groestl224/74",
        "groestl224/75",
        "groestl224/76",
        "groestl224/77",
        "groestl224/78",
        "groestl224/79",
        "groestl224/80",
        "groestl224/81",
        "groestl224/82",
        "groestl224/83",
        "groestl224/84",
        "groestl224/85",
        "groestl224/86",
        "groestl224/87",
        "groestl224/88",
        "groestl224/89",
        "groestl224/90",
        "groestl224/91",
        "groestl224/92",
        "groestl224/93",
        "groestl224/94",
        "groestl224/95",
        "groestl224/96",
        "groestl224/97",
        "groestl224/98",
        "groestl224/99",
        "groestl224/100",
        "groestl224/101",
        "groestl224/102",
        "groestl224/103",
        "groestl224/104",
        "groestl224/105",
        "groestl224/106",
        "groestl224/107",
        "groestl224/108",
        "groestl224/109",
        "groestl224/110",
        "groestl224/111",
        "groestl224/112",
        "groestl224/113",
        "groestl224/114",
        "groestl224/115",
        "groestl224/116",
        "groestl224/117",
        "groestl224/118",
        "groestl224/119",
        "groestl224/120",
        "groestl224/121",
        "groestl224/122",
        "groestl224/123",
        "groestl224/124",
        "groestl224/125",
        "groestl224/126",
        "groestl224/127",
        "groestl224/128",
        "groestl224/129",
        "groestl224/130",
        "groestl224/131",
        "groestl224/132",
        "groestl224/133",
        "groestl224/134",
        "groestl224/135",
        "groestl224/136",
        "groestl224/137",
        "groestl224/138",
        "groestl224/139",
        "groestl224/140",
        "groestl224/141",
        "groestl224/142",
        "groestl224/143",
        "groestl224/144",
        "groestl224/145",
        "groestl224/146",
        "groestl224/147",
        "groestl224/148",
        "groestl224/149",
        "groestl224/150",
        "groestl224/151",
        "groestl224/152",
        "groestl224/153",
        "groestl224/154",
        "groestl224/155",
        "groestl224/156",
        "groestl224/157",
        "groestl224/158",
        "groestl224/159",
        "groestl224/160",
        "groestl224/161",
        "groestl224/162",
        "groestl224/163",
        "groestl224/164",
        "groestl224/165",
        "groestl224/166",
        "groestl224/167",
        "groestl224/168",
        "groestl224/169",
        "groestl224/170",
        "groestl224/171",
        "groestl224/172",
        "groestl224/173",
        "groestl224/174",
        "groestl224/175",
        "groestl224/176",
        "groestl224/177",
        "groestl224/178",
        "groestl224/179",
        "groestl224/180",
        "groestl224/181",
        "groestl224/182",
        "groestl224/183",
        "groestl224/184",
        "groestl224/185",
        "groestl224/186",
        "groestl224/187",
        "groestl224/188",
        "groestl224/189",
        "groestl224/190",
        "groestl224/191",
        "groestl224/192",
        "groestl224/193",
        "groestl224/194",
        "groestl224/195",
        "groestl224/196",
        "groestl224/197",
        "groestl224/198",
        "groestl224/199",
        "groestl224/200",
        "groestl224/201",
        "groestl224/202",
        "groestl224/203",
        "groestl224/204",
        "groestl224/205",
        "groestl224/206",
        "groestl224/207",
        "groestl224/208",
        "groestl224/209",
        "groestl224/210",
        "groestl224/211",
        "groestl224/212",
        "groestl224/213",
        "groestl224/214",
        "groestl224/215",
        "groestl224/216",
        "groestl224/217",
        "groestl224/218",
        "groestl224/219",
        "groestl224/220",
        "groestl224/221",
        "groestl224/222",
        "groestl224/223",
        "groestl224/224",
        "groestl224/225",
        "groestl224/226",
        "groestl224/227",
        "groestl224/228",
        "groestl224/229",
        "groestl224/230",
        "groestl224/231",
        "groestl224/232",
        "groestl224/233",
        "groestl224/234",
        "groestl224/235",
        "groestl224/236",
        "groestl224/237",
        "groestl224/238",
        "groestl224/239",
        "groestl224/240",
        "groestl224/241",
        "groestl224/242",
        "groestl224/243",
        "groestl224/244",
        "groestl224/245",
        "groestl224/246",
        "groestl224/247",
        "groestl224/248",
        "groestl224/249",
        "groestl224/250",
        "groestl224/251",
        "groestl224/252",
        "groestl224/253",
        "groestl224/254",
        "groestl224/255",
    );
    main_test::<groestl::Groestl224>(&tests);
}

#[test]
fn groestl_256_main() {
    let tests = new_tests!(
        "groestl256/0",
        "groestl256/1",
        "groestl256/2",
        "groestl256/3",
        "groestl256/4",
        "groestl256/5",
        "groestl256/6",
        "groestl256/7",
        "groestl256/8",
        "groestl256/9",
        "groestl256/10",
        "groestl256/11",
        "groestl256/12",
        "groestl256/13",
        "groestl256/14",
        "groestl256/15",
        "groestl256/16",
        "groestl256/17",
        "groestl256/18",
        "groestl256/19",
        "groestl256/20",
        "groestl256/21",
        "groestl256/22",
        "groestl256/23",
        "groestl256/24",
        "groestl256/25",
        "groestl256/26",
        "groestl256/27",
        "groestl256/28",
        "groestl256/29",
        "groestl256/30",
        "groestl256/31",
        "groestl256/32",
        "groestl256/33",
        "groestl256/34",
        "groestl256/35",
        "groestl256/36",
        "groestl256/37",
        "groestl256/38",
        "groestl256/39",
        "groestl256/40",
        "groestl256/41",
        "groestl256/42",
        "groestl256/43",
        "groestl256/44",
        "groestl256/45",
        "groestl256/46",
        "groestl256/47",
        "groestl256/48",
        "groestl256/49",
        "groestl256/50",
        "groestl256/51",
        "groestl256/52",
        "groestl256/53",
        "groestl256/54",
        "groestl256/55",
        "groestl256/56",
        "groestl256/57",
        "groestl256/58",
        "groestl256/59",
        "groestl256/60",
        "groestl256/61",
        "groestl256/62",
        "groestl256/63",
        "groestl256/64",
        "groestl256/65",
        "groestl256/66",
        "groestl256/67",
        "groestl256/68",
        "groestl256/69",
        "groestl256/70",
        "groestl256/71",
        "groestl256/72",
        "groestl256/73",
        "groestl256/74",
        "groestl256/75",
        "groestl256/76",
        "groestl256/77",
        "groestl256/78",
        "groestl256/79",
        "groestl256/80",
        "groestl256/81",
        "groestl256/82",
        "groestl256/83",
        "groestl256/84",
        "groestl256/85",
        "groestl256/86",
        "groestl256/87",
        "groestl256/88",
        "groestl256/89",
        "groestl256/90",
        "groestl256/91",
        "groestl256/92",
        "groestl256/93",
        "groestl256/94",
        "groestl256/95",
        "groestl256/96",
        "groestl256/97",
        "groestl256/98",
        "groestl256/99",
        "groestl256/100",
        "groestl256/101",
        "groestl256/102",
        "groestl256/103",
        "groestl256/104",
        "groestl256/105",
        "groestl256/106",
        "groestl256/107",
        "groestl256/108",
        "groestl256/109",
        "groestl256/110",
        "groestl256/111",
        "groestl256/112",
        "groestl256/113",
        "groestl256/114",
        "groestl256/115",
        "groestl256/116",
        "groestl256/117",
        "groestl256/118",
        "groestl256/119",
        "groestl256/120",
        "groestl256/121",
        "groestl256/122",
        "groestl256/123",
        "groestl256/124",
        "groestl256/125",
        "groestl256/126",
        "groestl256/127",
        "groestl256/128",
        "groestl256/129",
        "groestl256/130",
        "groestl256/131",
        "groestl256/132",
        "groestl256/133",
        "groestl256/134",
        "groestl256/135",
        "groestl256/136",
        "groestl256/137",
        "groestl256/138",
        "groestl256/139",
        "groestl256/140",
        "groestl256/141",
        "groestl256/142",
        "groestl256/143",
        "groestl256/144",
        "groestl256/145",
        "groestl256/146",
        "groestl256/147",
        "groestl256/148",
        "groestl256/149",
        "groestl256/150",
        "groestl256/151",
        "groestl256/152",
        "groestl256/153",
        "groestl256/154",
        "groestl256/155",
        "groestl256/156",
        "groestl256/157",
        "groestl256/158",
        "groestl256/159",
        "groestl256/160",
        "groestl256/161",
        "groestl256/162",
        "groestl256/163",
        "groestl256/164",
        "groestl256/165",
        "groestl256/166",
        "groestl256/167",
        "groestl256/168",
        "groestl256/169",
        "groestl256/170",
        "groestl256/171",
        "groestl256/172",
        "groestl256/173",
        "groestl256/174",
        "groestl256/175",
        "groestl256/176",
        "groestl256/177",
        "groestl256/178",
        "groestl256/179",
        "groestl256/180",
        "groestl256/181",
        "groestl256/182",
        "groestl256/183",
        "groestl256/184",
        "groestl256/185",
        "groestl256/186",
        "groestl256/187",
        "groestl256/188",
        "groestl256/189",
        "groestl256/190",
        "groestl256/191",
        "groestl256/192",
        "groestl256/193",
        "groestl256/194",
        "groestl256/195",
        "groestl256/196",
        "groestl256/197",
        "groestl256/198",
        "groestl256/199",
        "groestl256/200",
        "groestl256/201",
        "groestl256/202",
        "groestl256/203",
        "groestl256/204",
        "groestl256/205",
        "groestl256/206",
        "groestl256/207",
        "groestl256/208",
        "groestl256/209",
        "groestl256/210",
        "groestl256/211",
        "groestl256/212",
        "groestl256/213",
        "groestl256/214",
        "groestl256/215",
        "groestl256/216",
        "groestl256/217",
        "groestl256/218",
        "groestl256/219",
        "groestl256/220",
        "groestl256/221",
        "groestl256/222",
        "groestl256/223",
        "groestl256/224",
        "groestl256/225",
        "groestl256/226",
        "groestl256/227",
        "groestl256/228",
        "groestl256/229",
        "groestl256/230",
        "groestl256/231",
        "groestl256/232",
        "groestl256/233",
        "groestl256/234",
        "groestl256/235",
        "groestl256/236",
        "groestl256/237",
        "groestl256/238",
        "groestl256/239",
        "groestl256/240",
        "groestl256/241",
        "groestl256/242",
        "groestl256/243",
        "groestl256/244",
        "groestl256/245",
        "groestl256/246",
        "groestl256/247",
        "groestl256/248",
        "groestl256/249",
        "groestl256/250",
        "groestl256/251",
        "groestl256/252",
        "groestl256/253",
        "groestl256/254",
        "groestl256/255",
    );
    main_test::<groestl::Groestl256>(&tests);
}

#[test]
fn groestl_384_main() {
    let tests = new_tests!(
        "groestl384/0",
        "groestl384/1",
        "groestl384/2",
        "groestl384/3",
        "groestl384/4",
        "groestl384/5",
        "groestl384/6",
        "groestl384/7",
        "groestl384/8",
        "groestl384/9",
        "groestl384/10",
        "groestl384/11",
        "groestl384/12",
        "groestl384/13",
        "groestl384/14",
        "groestl384/15",
        "groestl384/16",
        "groestl384/17",
        "groestl384/18",
        "groestl384/19",
        "groestl384/20",
        "groestl384/21",
        "groestl384/22",
        "groestl384/23",
        "groestl384/24",
        "groestl384/25",
        "groestl384/26",
        "groestl384/27",
        "groestl384/28",
        "groestl384/29",
        "groestl384/30",
        "groestl384/31",
        "groestl384/32",
        "groestl384/33",
        "groestl384/34",
        "groestl384/35",
        "groestl384/36",
        "groestl384/37",
        "groestl384/38",
        "groestl384/39",
        "groestl384/40",
        "groestl384/41",
        "groestl384/42",
        "groestl384/43",
        "groestl384/44",
        "groestl384/45",
        "groestl384/46",
        "groestl384/47",
        "groestl384/48",
        "groestl384/49",
        "groestl384/50",
        "groestl384/51",
        "groestl384/52",
        "groestl384/53",
        "groestl384/54",
        "groestl384/55",
        "groestl384/56",
        "groestl384/57",
        "groestl384/58",
        "groestl384/59",
        "groestl384/60",
        "groestl384/61",
        "groestl384/62",
        "groestl384/63",
        "groestl384/64",
        "groestl384/65",
        "groestl384/66",
        "groestl384/67",
        "groestl384/68",
        "groestl384/69",
        "groestl384/70",
        "groestl384/71",
        "groestl384/72",
        "groestl384/73",
        "groestl384/74",
        "groestl384/75",
        "groestl384/76",
        "groestl384/77",
        "groestl384/78",
        "groestl384/79",
        "groestl384/80",
        "groestl384/81",
        "groestl384/82",
        "groestl384/83",
        "groestl384/84",
        "groestl384/85",
        "groestl384/86",
        "groestl384/87",
        "groestl384/88",
        "groestl384/89",
        "groestl384/90",
        "groestl384/91",
        "groestl384/92",
        "groestl384/93",
        "groestl384/94",
        "groestl384/95",
        "groestl384/96",
        "groestl384/97",
        "groestl384/98",
        "groestl384/99",
        "groestl384/100",
        "groestl384/101",
        "groestl384/102",
        "groestl384/103",
        "groestl384/104",
        "groestl384/105",
        "groestl384/106",
        "groestl384/107",
        "groestl384/108",
        "groestl384/109",
        "groestl384/110",
        "groestl384/111",
        "groestl384/112",
        "groestl384/113",
        "groestl384/114",
        "groestl384/115",
        "groestl384/116",
        "groestl384/117",
        "groestl384/118",
        "groestl384/119",
        "groestl384/120",
        "groestl384/121",
        "groestl384/122",
        "groestl384/123",
        "groestl384/124",
        "groestl384/125",
        "groestl384/126",
        "groestl384/127",
        "groestl384/128",
        "groestl384/129",
        "groestl384/130",
        "groestl384/131",
        "groestl384/132",
        "groestl384/133",
        "groestl384/134",
        "groestl384/135",
        "groestl384/136",
        "groestl384/137",
        "groestl384/138",
        "groestl384/139",
        "groestl384/140",
        "groestl384/141",
        "groestl384/142",
        "groestl384/143",
        "groestl384/144",
        "groestl384/145",
        "groestl384/146",
        "groestl384/147",
        "groestl384/148",
        "groestl384/149",
        "groestl384/150",
        "groestl384/151",
        "groestl384/152",
        "groestl384/153",
        "groestl384/154",
        "groestl384/155",
        "groestl384/156",
        "groestl384/157",
        "groestl384/158",
        "groestl384/159",
        "groestl384/160",
        "groestl384/161",
        "groestl384/162",
        "groestl384/163",
        "groestl384/164",
        "groestl384/165",
        "groestl384/166",
        "groestl384/167",
        "groestl384/168",
        "groestl384/169",
        "groestl384/170",
        "groestl384/171",
        "groestl384/172",
        "groestl384/173",
        "groestl384/174",
        "groestl384/175",
        "groestl384/176",
        "groestl384/177",
        "groestl384/178",
        "groestl384/179",
        "groestl384/180",
        "groestl384/181",
        "groestl384/182",
        "groestl384/183",
        "groestl384/184",
        "groestl384/185",
        "groestl384/186",
        "groestl384/187",
        "groestl384/188",
        "groestl384/189",
        "groestl384/190",
        "groestl384/191",
        "groestl384/192",
        "groestl384/193",
        "groestl384/194",
        "groestl384/195",
        "groestl384/196",
        "groestl384/197",
        "groestl384/198",
        "groestl384/199",
        "groestl384/200",
        "groestl384/201",
        "groestl384/202",
        "groestl384/203",
        "groestl384/204",
        "groestl384/205",
        "groestl384/206",
        "groestl384/207",
        "groestl384/208",
        "groestl384/209",
        "groestl384/210",
        "groestl384/211",
        "groestl384/212",
        "groestl384/213",
        "groestl384/214",
        "groestl384/215",
        "groestl384/216",
        "groestl384/217",
        "groestl384/218",
        "groestl384/219",
        "groestl384/220",
        "groestl384/221",
        "groestl384/222",
        "groestl384/223",
        "groestl384/224",
        "groestl384/225",
        "groestl384/226",
        "groestl384/227",
        "groestl384/228",
        "groestl384/229",
        "groestl384/230",
        "groestl384/231",
        "groestl384/232",
        "groestl384/233",
        "groestl384/234",
        "groestl384/235",
        "groestl384/236",
        "groestl384/237",
        "groestl384/238",
        "groestl384/239",
        "groestl384/240",
        "groestl384/241",
        "groestl384/242",
        "groestl384/243",
        "groestl384/244",
        "groestl384/245",
        "groestl384/246",
        "groestl384/247",
        "groestl384/248",
        "groestl384/249",
        "groestl384/250",
        "groestl384/251",
        "groestl384/252",
        "groestl384/253",
        "groestl384/254",
        "groestl384/255",
    );
    main_test::<groestl::Groestl384>(&tests);
}

#[test]
fn groestl_512_main() {
    let tests = new_tests!(
        "groestl512/0",
        "groestl512/1",
        "groestl512/2",
        "groestl512/3",
        "groestl512/4",
        "groestl512/5",
        "groestl512/6",
        "groestl512/7",
        "groestl512/8",
        "groestl512/9",
        "groestl512/10",
        "groestl512/11",
        "groestl512/12",
        "groestl512/13",
        "groestl512/14",
        "groestl512/15",
        "groestl512/16",
        "groestl512/17",
        "groestl512/18",
        "groestl512/19",
        "groestl512/20",
        "groestl512/21",
        "groestl512/22",
        "groestl512/23",
        "groestl512/24",
        "groestl512/25",
        "groestl512/26",
        "groestl512/27",
        "groestl512/28",
        "groestl512/29",
        "groestl512/30",
        "groestl512/31",
        "groestl512/32",
        "groestl512/33",
        "groestl512/34",
        "groestl512/35",
        "groestl512/36",
        "groestl512/37",
        "groestl512/38",
        "groestl512/39",
        "groestl512/40",
        "groestl512/41",
        "groestl512/42",
        "groestl512/43",
        "groestl512/44",
        "groestl512/45",
        "groestl512/46",
        "groestl512/47",
        "groestl512/48",
        "groestl512/49",
        "groestl512/50",
        "groestl512/51",
        "groestl512/52",
        "groestl512/53",
        "groestl512/54",
        "groestl512/55",
        "groestl512/56",
        "groestl512/57",
        "groestl512/58",
        "groestl512/59",
        "groestl512/60",
        "groestl512/61",
        "groestl512/62",
        "groestl512/63",
        "groestl512/64",
        "groestl512/65",
        "groestl512/66",
        "groestl512/67",
        "groestl512/68",
        "groestl512/69",
        "groestl512/70",
        "groestl512/71",
        "groestl512/72",
        "groestl512/73",
        "groestl512/74",
        "groestl512/75",
        "groestl512/76",
        "groestl512/77",
        "groestl512/78",
        "groestl512/79",
        "groestl512/80",
        "groestl512/81",
        "groestl512/82",
        "groestl512/83",
        "groestl512/84",
        "groestl512/85",
        "groestl512/86",
        "groestl512/87",
        "groestl512/88",
        "groestl512/89",
        "groestl512/90",
        "groestl512/91",
        "groestl512/92",
        "groestl512/93",
        "groestl512/94",
        "groestl512/95",
        "groestl512/96",
        "groestl512/97",
        "groestl512/98",
        "groestl512/99",
        "groestl512/100",
        "groestl512/101",
        "groestl512/102",
        "groestl512/103",
        "groestl512/104",
        "groestl512/105",
        "groestl512/106",
        "groestl512/107",
        "groestl512/108",
        "groestl512/109",
        "groestl512/110",
        "groestl512/111",
        "groestl512/112",
        "groestl512/113",
        "groestl512/114",
        "groestl512/115",
        "groestl512/116",
        "groestl512/117",
        "groestl512/118",
        "groestl512/119",
        "groestl512/120",
        "groestl512/121",
        "groestl512/122",
        "groestl512/123",
        "groestl512/124",
        "groestl512/125",
        "groestl512/126",
        "groestl512/127",
        "groestl512/128",
        "groestl512/129",
        "groestl512/130",
        "groestl512/131",
        "groestl512/132",
        "groestl512/133",
        "groestl512/134",
        "groestl512/135",
        "groestl512/136",
        "groestl512/137",
        "groestl512/138",
        "groestl512/139",
        "groestl512/140",
        "groestl512/141",
        "groestl512/142",
        "groestl512/143",
        "groestl512/144",
        "groestl512/145",
        "groestl512/146",
        "groestl512/147",
        "groestl512/148",
        "groestl512/149",
        "groestl512/150",
        "groestl512/151",
        "groestl512/152",
        "groestl512/153",
        "groestl512/154",
        "groestl512/155",
        "groestl512/156",
        "groestl512/157",
        "groestl512/158",
        "groestl512/159",
        "groestl512/160",
        "groestl512/161",
        "groestl512/162",
        "groestl512/163",
        "groestl512/164",
        "groestl512/165",
        "groestl512/166",
        "groestl512/167",
        "groestl512/168",
        "groestl512/169",
        "groestl512/170",
        "groestl512/171",
        "groestl512/172",
        "groestl512/173",
        "groestl512/174",
        "groestl512/175",
        "groestl512/176",
        "groestl512/177",
        "groestl512/178",
        "groestl512/179",
        "groestl512/180",
        "groestl512/181",
        "groestl512/182",
        "groestl512/183",
        "groestl512/184",
        "groestl512/185",
        "groestl512/186",
        "groestl512/187",
        "groestl512/188",
        "groestl512/189",
        "groestl512/190",
        "groestl512/191",
        "groestl512/192",
        "groestl512/193",
        "groestl512/194",
        "groestl512/195",
        "groestl512/196",
        "groestl512/197",
        "groestl512/198",
        "groestl512/199",
        "groestl512/200",
        "groestl512/201",
        "groestl512/202",
        "groestl512/203",
        "groestl512/204",
        "groestl512/205",
        "groestl512/206",
        "groestl512/207",
        "groestl512/208",
        "groestl512/209",
        "groestl512/210",
        "groestl512/211",
        "groestl512/212",
        "groestl512/213",
        "groestl512/214",
        "groestl512/215",
        "groestl512/216",
        "groestl512/217",
        "groestl512/218",
        "groestl512/219",
        "groestl512/220",
        "groestl512/221",
        "groestl512/222",
        "groestl512/223",
        "groestl512/224",
        "groestl512/225",
        "groestl512/226",
        "groestl512/227",
        "groestl512/228",
        "groestl512/229",
        "groestl512/230",
        "groestl512/231",
        "groestl512/232",
        "groestl512/233",
        "groestl512/234",
        "groestl512/235",
        "groestl512/236",
        "groestl512/237",
        "groestl512/238",
        "groestl512/239",
        "groestl512/240",
        "groestl512/241",
        "groestl512/242",
        "groestl512/243",
        "groestl512/244",
        "groestl512/245",
        "groestl512/246",
        "groestl512/247",
        "groestl512/248",
        "groestl512/249",
        "groestl512/250",
        "groestl512/251",
        "groestl512/252",
        "groestl512/253",
        "groestl512/254",
        "groestl512/255",
    );
    main_test::<groestl::Groestl512>(&tests);
}