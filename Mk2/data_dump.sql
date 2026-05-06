--
-- PostgreSQL database dump
--

\restrict 0Jd2XI8L8bqk7b34uHpYMUnxdJFmpEC0rzGxTDTYx3HhcZ86bFYIxWD2ImpJnpV

-- Dumped from database version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.users VALUES (1, 'testSQL', 'testSQL', '2026-05-06T02:43:36.681696+00:00', '2026-05-06T02:43:36.681706+00:00');
INSERT INTO public.users VALUES (3, 'testpost', 'testpost', '2026-05-06T02:46:06.320306+00:00', '2026-05-06T02:46:06.320319+00:00');
INSERT INTO public.users VALUES (5, 'Test User', 'Test User', '2026-05-06T06:30:44.620671+00:00', '2026-05-06T06:30:44.620683+00:00');
INSERT INTO public.users VALUES (6, 'testHW', 'testHW', '2026-05-06T06:55:38.377149+00:00', '2026-05-06T06:55:38.377161+00:00');


--
-- Data for Name: vaults; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.vaults VALUES (1, 1, 'testSQL1', 'LOCKED', '2026-05-06T02:43:36.722958+00:00', '2026-05-06T02:43:36.722966+00:00');
INSERT INTO public.vaults VALUES (3, 3, 'test', 'LOCKED', '2026-05-06T02:46:06.366641+00:00', '2026-05-06T02:46:06.366649+00:00');
INSERT INTO public.vaults VALUES (5, 5, 'Test', 'LOCKED', '2026-05-06T06:30:44.657505+00:00', '2026-05-06T06:30:44.657514+00:00');
INSERT INTO public.vaults VALUES (6, 5, 'Test1', 'LOCKED', '2026-05-06T06:30:56.255107+00:00', '2026-05-06T06:30:56.255117+00:00');
INSERT INTO public.vaults VALUES (7, 6, 'testHW', 'LOCKED', '2026-05-06T06:55:38.388768+00:00', '2026-05-06T06:55:38.388777+00:00');
INSERT INTO public.vaults VALUES (9, 5, 'TestPersonalHW', 'LOCKED', '2026-05-06T17:05:06.511600+00:00', '2026-05-06T17:05:06.511608+00:00');


--
-- Data for Name: access_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.access_logs VALUES (7, 3, 3, 'initialize', 'hardware_gated', 1, 'Vault initialized', '2026-05-06T02:46:06.609064+00:00');
INSERT INTO public.access_logs VALUES (20, 5, 5, 'initialize', 'hardware_gated', 1, 'Vault initialized', '2026-05-06T06:30:44.860502+00:00');
INSERT INTO public.access_logs VALUES (21, 5, 5, 'unlock', 'software_only', 1, 'Vault unlocked', '2026-05-06T06:30:45.070867+00:00');
INSERT INTO public.access_logs VALUES (22, 5, 5, 'lock', NULL, 1, 'Vault locked', '2026-05-06T06:30:46.818770+00:00');
INSERT INTO public.access_logs VALUES (23, 6, 5, 'initialize', 'hardware_gated', 1, 'Vault initialized', '2026-05-06T06:30:56.446024+00:00');
INSERT INTO public.access_logs VALUES (24, 6, 5, 'unlock', 'software_only', 1, 'Vault unlocked', '2026-05-06T06:30:56.648339+00:00');
INSERT INTO public.access_logs VALUES (25, 6, 5, 'lock', NULL, 1, 'Vault locked', '2026-05-06T06:30:58.524105+00:00');
INSERT INTO public.access_logs VALUES (26, 7, 6, 'initialize', 'hardware_gated', 1, 'Vault initialized', '2026-05-06T06:55:38.496875+00:00');
INSERT INTO public.access_logs VALUES (27, 7, 6, 'unlock', 'hardware_gated', 1, 'Vault unlocked', '2026-05-06T06:58:00.209788+00:00');
INSERT INTO public.access_logs VALUES (28, 7, 6, 'lock', NULL, 1, 'Vault locked', '2026-05-06T06:58:33.630698+00:00');
INSERT INTO public.access_logs VALUES (32, 9, 5, 'initialize', 'hardware_gated', 1, 'Vault initialized', '2026-05-06T17:05:06.752434+00:00');


--
-- Data for Name: auth_credentials; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.auth_credentials VALUES (2, 3, 'S/n0x43SCBF0FnV6qboqIg==', 'gPQrRxVLgO28hv4mVW/nSTB/Al6RoXHpZyk4eiePOOZG36VN20nJnUkPpzWVKRlP', 'fIs9q4Nl/P/Echr/HPB3RfVdBsDOeyYj', 'argon2id', 65536, 3, 4, '2026-05-06T02:46:06.498407+00:00', '2026-05-06T02:46:06.498417+00:00');
INSERT INTO public.auth_credentials VALUES (4, 5, '8mi6jVUFisqc+Ea7YbMzkw==', 'HD1+cijXJQQY2A2t9g3iZQtJGDXQcGJGNZqr/R1vDSnZ+OlbuVsAesYSBcn3ReWI', 'lIXZoy6L/RsQ00vpNuaHzLdqgq4fuqtI', 'argon2id', 65536, 3, 4, '2026-05-06T06:30:44.777690+00:00', '2026-05-06T06:30:44.777699+00:00');
INSERT INTO public.auth_credentials VALUES (5, 6, 'Fp5TpEe3Vsu3Wka3JA79+A==', 'fZGCLq5AfTH/3WELeA2BHiINN4YBw1xkrGiCNLrZX1dsLXeDJ2WGWUYSJ4F1Lg7D', 'zP3pbNI6Oio5rYpKe5H9NBJUAfvba2I4', 'argon2id', 65536, 3, 4, '2026-05-06T06:30:56.377553+00:00', '2026-05-06T06:30:56.377563+00:00');
INSERT INTO public.auth_credentials VALUES (6, 7, 'F/FL5BKlPx6ZLiBKO1kNMQ==', '212oo7iLImc68Kz+6qjR3aUW8Le76nW4rWgU2D0+svrP6UDax9IxGa/d8sYMnqu6', 'dA3wIRIxAjZ0nS+cRqnDLDnXZ3D2mRVl', 'argon2id', 65536, 3, 4, '2026-05-06T06:55:38.463640+00:00', '2026-05-06T06:55:38.463656+00:00');
INSERT INTO public.auth_credentials VALUES (8, 9, 'gOMvu5HLPE20rquaVgQaIw==', 'wkZPwGmfh2hRbkkMxI2a5XWFXFd8rMNvnQEkUMnh6pxr47/SlhhoI0lzQmKJGKj7', 'rwdNowuT3xeJtlcvIxw2PS81DBGsrUFh', 'argon2id', 65536, 3, 4, '2026-05-06T17:05:06.641284+00:00', '2026-05-06T17:05:06.641294+00:00');


--
-- Data for Name: hardware_auth; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.hardware_auth VALUES (1, 3, 'd43d5d580f40e6a7f645a128a5ae33ce2509a642f8d6158745fc61f24b2025d8', 'UrEO/BWpxeTV1E3O82VbPg==', 1, 0, NULL, '2026-05-06T02:46:06.530376+00:00', '2026-05-06T02:46:06.530387+00:00');
INSERT INTO public.hardware_auth VALUES (2, 7, '689ce8d5b9197a020f7a2c0c33dfb0d512c6684b7f497e72444915ae444dfdd8', 'ebJoZxdIhdUoJk85YIdW3Q==', 1, 0, '2026-05-06T06:57:22.187864+00:00', '2026-05-06T06:55:38.474842+00:00', '2026-05-06T06:55:38.474855+00:00');
INSERT INTO public.hardware_auth VALUES (3, 9, 'f3afa7c131f026cc54011372ce780f701af30f49389ace9a1d0a09ce7389cafe', 'oFhQAgzg5Q0gGOh1yM7+gw==', 1, 0, NULL, '2026-05-06T17:05:06.678124+00:00', '2026-05-06T17:05:06.678134+00:00');


--
-- Data for Name: hardware_devices; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: vault_data; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.vault_data VALUES (4, 5, 'Ei0Dcfih70wElTz7WAqCwSYugwoLxSKaCjsF4zGHmA==', 'xtIwL9qkGe3JJEURzR1OmBlxVrrGV+tf', 'xchacha20-poly1305', '2026-05-06T06:30:44.819109+00:00', '2026-05-06T06:30:44.819119+00:00');
INSERT INTO public.vault_data VALUES (5, 6, '2/AnhY4qgNHMPQzyzWLBfc4rUbk4rrQIwvtWhlH+oA==', 'Y594x8k8/tqfzsXcPzGVPr837YneE/JM', 'xchacha20-poly1305', '2026-05-06T06:30:56.409259+00:00', '2026-05-06T06:30:56.409270+00:00');
INSERT INTO public.vault_data VALUES (6, 7, 'iW2gvXkKWf3YWN8Qjk1dvJAl1DCGTxf/X1CRkwqCbw==', 'PjsAOa3WbYSVjRvUUDFO33NoXD3mXJWW', 'xchacha20-poly1305', '2026-05-06T06:55:38.486129+00:00', '2026-05-06T06:55:38.486139+00:00');
INSERT INTO public.vault_data VALUES (2, 3, 'PVcgKqd597s/rM+1nat8yYBAB/sRRBos91sXrSw4rw==', 'hMaKKh23RAyLDIayrGatHFVlOvFeC4ao', 'xchacha20-poly1305', '2026-05-06T02:46:06.572445+00:00', '2026-05-06T02:46:06.572455+00:00');
INSERT INTO public.vault_data VALUES (8, 9, 'jOUnHpI1bbCL5KHgJ8WJIwnR5kwkGfMaKSK8wVN/kw==', 'BBq9L04fMwtmzWvE16ISTFAnRA036gZm', 'xchacha20-poly1305', '2026-05-06T17:05:06.721564+00:00', '2026-05-06T17:05:06.721573+00:00');


--
-- Data for Name: vault_policy; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.vault_policy VALUES (2, 3, 1, 0, 60, '2026-05-06T02:46:06.397617+00:00', '2026-05-06T02:46:06.397628+00:00');
INSERT INTO public.vault_policy VALUES (4, 5, 0, 1, 60, '2026-05-06T06:30:44.689058+00:00', '2026-05-06T06:30:44.689069+00:00');
INSERT INTO public.vault_policy VALUES (5, 6, 0, 1, 60, '2026-05-06T06:30:56.287231+00:00', '2026-05-06T06:30:56.287241+00:00');
INSERT INTO public.vault_policy VALUES (6, 7, 1, 0, 60, '2026-05-06T06:55:38.401619+00:00', '2026-05-06T06:55:38.401629+00:00');
INSERT INTO public.vault_policy VALUES (8, 9, 1, 0, 60, '2026-05-06T17:05:06.543832+00:00', '2026-05-06T17:05:06.543841+00:00');


--
-- Name: access_logs_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.access_logs_log_id_seq', 43, true);


--
-- Name: auth_credentials_auth_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_credentials_auth_id_seq', 8, true);


--
-- Name: hardware_auth_hardware_auth_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.hardware_auth_hardware_auth_id_seq', 3, true);


--
-- Name: hardware_devices_device_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.hardware_devices_device_id_seq', 1, false);


--
-- Name: users_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_user_id_seq', 6, true);


--
-- Name: vault_data_data_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.vault_data_data_id_seq', 8, true);


--
-- Name: vault_policy_policy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.vault_policy_policy_id_seq', 8, true);


--
-- Name: vaults_vault_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.vaults_vault_id_seq', 9, true);


--
-- PostgreSQL database dump complete
--

\unrestrict 0Jd2XI8L8bqk7b34uHpYMUnxdJFmpEC0rzGxTDTYx3HhcZ86bFYIxWD2ImpJnpV

