# =====================================================  
# 🛡️ Kashaf Ultimate Phishing Analyzer API v4.0  
# =====================================================  
# 324 دومين خطر | 100 خدمة اختصار | 100 علامة تجارية  
# Azure AI Foundry + Claude + Content Safety  
# =====================================================  
  
from typing import Optional, List, Literal, Dict, Any, Tuple  
from fastapi import FastAPI, HTTPException, File, UploadFile, Query  
from fastapi.middleware.cors import CORSMiddleware  
from pydantic import BaseModel, Field  
from datetime import datetime  
from urllib.parse import urlparse  
from collections import defaultdict  
import os  
import httpx  
import json  
import re  
from enum import Enum  
from dotenv import load_dotenv  
# AWS Bedrock - Anthropic Claude  
import boto3  
import asyncio 
load_dotenv()  
  
  
# =============================================================================  
# 🔧 CONFIGURATION  
# =============================================================================  
class Config:  
    """إعدادات التطبيق"""  
      
    # Azure AI Foundry - Anthropic  
    # AWS Bedrock - Anthropic Claude  
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")  
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")  
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")  
    BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-sonnet-4-6")  
  
    # للتوافق مع بقية الكود  
    AZURE_ANTHROPIC_DEPLOYMENT = BEDROCK_MODEL_ID  
    AZURE_ANTHROPIC_API_KEY = AWS_ACCESS_KEY_ID  
    # Google APIs  
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")  
    WEBRISK_API_KEY = os.getenv("WEBRISK_API_KEY", "")  
      
    # WHOIS  
    WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")  
      
    # Azure AI Vision  
    AZURE_AI_VISION_BASE = os.getenv("AZURE_AI_VISION_BASE", "").rstrip('/')  
    AZURE_AI_VISION_KEY = os.getenv("AZURE_AI_VISION_KEY", "")  
      
    # Azure Content Safety  
    AZURE_AI_CONTENT_SAFETY_BASE = os.getenv(  
        "AZURE_AI_CONTENT_SAFETY_BASE",  
        "https://mosta-m9q4ne8y-eastus2.cognitiveservices.azure.com"  
    ).rstrip('/')  
    AZURE_AI_CONTENT_SAFETY_KEY = os.getenv(  
        "AZURE_AI_CONTENT_SAFETY_KEY",  
        "4Shlwh73wzLLW"  
    )  
      
    # Anthropic Client  
    _client = None  
      
    @classmethod  
    def get_client(cls):  
        if cls._client is None:  
            session = boto3.Session(  
                aws_access_key_id=cls.AWS_ACCESS_KEY_ID if cls.AWS_ACCESS_KEY_ID else None,  
                aws_secret_access_key=cls.AWS_SECRET_ACCESS_KEY if cls.AWS_SECRET_ACCESS_KEY else None,  
                region_name=cls.AWS_REGION  
            )  
            cls._client = session.client("bedrock-runtime", region_name=cls.AWS_REGION)  
        return cls._client  
      
    @classmethod  
    def get_active_services(cls) -> Dict[str, bool]:  
        return {  
            "anthropic_claude": bool(cls.AZURE_ANTHROPIC_API_KEY),  
            "google_safe_browsing": bool(cls.GOOGLE_SAFE_BROWSING_API_KEY),  
            "google_web_risk": bool(cls.WEBRISK_API_KEY),  
            "whois": bool(cls.WHOIS_API_KEY),  
            "azure_vision": bool(cls.AZURE_AI_VISION_KEY and cls.AZURE_AI_VISION_BASE),  
            "azure_content_safety": bool(cls.AZURE_AI_CONTENT_SAFETY_KEY and cls.AZURE_AI_CONTENT_SAFETY_BASE),  
        }  
  
  
# =============================================================================  
# 🌐 FASTAPI APP  
# =============================================================================  
app = FastAPI(  
    title="Kashaf Ultimate Phishing Analyzer",  
    description="🛡️ نظام كشف متكامل للاحتيال والتصيد الإلكتروني - 324 دومين | 100 مختصر | 100 علامة",  
    version="4.0.0",  
    docs_url="/docs",  
    redoc_url="/redoc"  
)  
  
app.add_middleware(  
    CORSMiddleware,  
    allow_origins=["*"],  
    allow_credentials=True,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)  
  
  
# =============================================================================  
# 🔥 قاعدة البيانات الضخمة - 324 دومين خطر  
# =============================================================================  
HIGH_RISK_DOMAINS = {  
    # ===== منصات إنشاء المواقع المجانية (50) =====  
    "wixsite.com", "wix.com", "weebly.com", "wordpress.com", "wordpress.org",  
    "blogspot.com", "blogger.com", "tumblr.com", "medium.com", "ghost.io",  
    "squarespace.com", "jimdo.com", "site123.com", "webnode.com", "strikingly.com",  
    "carrd.co", "webflow.io", "tilda.cc", "tilda.ws", "readymag.com",  
    "cargocollective.com", "carbonmade.com", "myportfolio.com", "format.com", "dunked.com",  
    "portfoliobox.net", "uxfolio.com", "journoportfolio.com", "fabrik.io", "semplice.com",  
    "cargo.site", "muckrack.com", "contently.com", "clippings.me", "pressfolios.com",  
    "exposure.co", "atavist.com", "shorthand.com", "creatavist.com", "hatch.co",  
    "launchaco.com", "landen.co", "versoly.com", "dorik.io", "typedream.com",  
    "softr.io", "glide.page", "sheet2site.com", "table2site.com", "pory.io",  
      
    # ===== استضافة مجانية (50) =====  
    "000webhostapp.com", "000webhost.com", "infinityfreeapp.com", "infinityfree.net",  
    "freehostia.com", "freehosting.com", "byethost.com", "byet.host", "awardspace.com",  
    "x10hosting.com", "hostinger.com", "freenom.com", "rf.gd", "epizy.com",  
    "ezyro.com", "unaux.com", "myftp.org", "myftp.biz", "servequake.com",  
    "servehttp.com", "serveftp.com", "redirectme.net", "hopto.org", "zapto.org",  
    "sytes.net", "ddns.net", "no-ip.org", "no-ip.biz", "no-ip.info",  
    "duckdns.org", "freedns.afraid.org", "dynu.com", "changeip.com", "dnsdynamic.org",  
    "freeddns.org", "noip.com", "afraid.org", "dtdns.com", "zoneedit.com",  
    "dnsever.com", "cloudns.net", "he.net", "dnsmadeeasy.com", "easydns.com",  
    "hostry.com", "profreehost.com", "atwebpages.com", "freewebhostingarea.com", "50webs.com",  
      
    # ===== منصات النشر والمدونات (30) =====  
    "notion.so", "notion.site", "coda.io", "airtable.com", "baserow.io",  
    "gitbook.io", "gitbook.com", "readme.io", "readme.com", "docsify.js.org",  
    "mkdocs.org", "sphinx-doc.org", "docusaurus.io", "vuepress.vuejs.org", "hexo.io",  
    "jekyllrb.com", "gohugo.io", "11ty.dev", "gatsbyjs.com", "nextjs.org",  
    "nuxtjs.org", "sveltekit.dev", "astro.build", "remix.run", "blitz.js.org",  
    "redwoodjs.com", "keystonejs.com", "strapi.io", "directus.io", "sanity.io",  
      
    # ===== منصات النماذج والاستبيانات (30) =====  
    "typeform.com", "jotform.com", "google.com/forms", "forms.gle", "docs.google.com",  
    "surveymonkey.com", "surveygizmo.com", "alchemer.com", "qualtrics.com", "formstack.com",  
    "wufoo.com", "cognito.com", "formsite.com", "emailmeform.com", "formspree.io",  
    "formspark.io", "getform.io", "basin.io", "formcarry.com", "formsubmit.co",  
    "netlify.com/forms", "staticforms.xyz", "kwes.io", "formkeep.com", "99inbound.com",  
    "paperform.co", "tally.so", "fillout.com", "reform.app", "feathery.io",  
      
    # ===== استضافة سحابية ومطورين (50) =====  
    "netlify.app", "netlify.com", "vercel.app", "vercel.com", "github.io",  
    "github.com", "gitlab.io", "gitlab.com", "bitbucket.io", "bitbucket.org",  
    "herokuapp.com", "heroku.com", "firebaseapp.com", "firebase.google.com", "web.app",  
    "appspot.com", "cloudfunctions.net", "run.app", "azurewebsites.net", "azure.com",  
    "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "amplifyapp.com", "awsapprunner.com",  
    "digitalocean.app", "ondigitalocean.app", "pages.dev", "workers.dev", "r2.dev",  
    "fly.dev", "fly.io", "railway.app", "render.com", "onrender.com",  
    "cyclic.sh", "deta.dev", "deta.sh", "replit.com", "repl.co",  
    "glitch.com", "glitch.me", "codesandbox.io", "stackblitz.com", "gitpod.io",  
    "codepen.io", "jsfiddle.net", "plnkr.co", "runkit.com", "observablehq.com",  
      
    # ===== منصات الروابط الحيوية (30) =====  
    "linktr.ee", "linktree.com", "bio.link", "bio.fm", "lnk.bio",  
    "tap.bio", "campsite.bio", "beacons.ai", "beacons.page", "stan.store",  
    "hoo.be", "snipfeed.co", "solo.to", "withkoji.com", "koji.to",  
    "lynx.page", "lynxinbio.com", "milkshake.app", "contactinbio.com", "linkpop.com",  
    "flowpage.com", "flowcode.com", "shorby.com", "tap.link", "manylink.co",  
    "biolinky.co", "instabio.cc", "linkfly.to", "linkjoy.io", "smartbio.com",  
      
    # ===== منصات التجارة والدفع المشبوهة (30) =====  
    "gumroad.com", "sellfy.com", "payhip.com", "sendowl.com", "paddle.com",  
    "lemonsqueezy.com", "podia.com", "teachable.com", "thinkific.com", "kajabi.com",  
    "samcart.com", "clickfunnels.com", "kartra.com", "systeme.io", "builderall.com",  
    "groovefunnels.com", "getresponse.com", "convertkit.com", "mailchimp.com", "sendinblue.com",  
    "ko-fi.com", "buymeacoffee.com", "patreon.com", "memberful.com", "memberstack.com",  
    "outseta.com", "pico.link", "fourthwall.com", "bigcartel.com", "ecwid.com",  
      
    # ===== منصات مشاركة الملفات (24) =====  
    "dropbox.com", "wetransfer.com", "sendspace.com", "mediafire.com", "mega.nz",  
    "mega.io", "zippyshare.com", "uploadfiles.io", "file.io", "gofile.io",  
    "anonfiles.com", "bayfiles.com", "letsupload.cc", "uploadhaven.com", "upload.ee",  
    "filedropper.com", "filefactory.com", "turbobit.net", "hitfile.net", "katfile.com",  
    "rapidgator.net", "nitroflare.com", "uploaded.net", "uploadgig.com",  
      
    # ===== خدمات البريد المؤقت (30) =====  
    "tempmail.com", "temp-mail.org", "guerrillamail.com", "mailinator.com", "10minutemail.com",  
    "throwawaymail.com", "fakeinbox.com", "getnada.com", "mohmal.com", "emailondeck.com",  
    "tempr.email", "tempail.com", "tmpmail.org", "tmpmail.net", "dispostable.com",  
    "mailnesia.com", "mytrashmail.com", "mt2015.com", "sharklasers.com", "spam4.me",  
    "grr.la", "guerrillamail.info", "pokemail.net", "spamgourmet.com", "spamex.com",  
    "trashmail.com", "trashmail.net", "yopmail.com", "maildrop.cc", "inboxkitten.com",  
}  
  
# =============================================================================  
# 🔗 100 خدمة اختصار روابط  
# =============================================================================  
LINK_SHORTENERS = {  
    # ===== الأكثر شيوعاً (30) =====  
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl",  
    "ow.ly", "buff.ly", "is.gd", "v.gd", "short.io",  
    "rebrand.ly", "cutt.ly", "bl.ink", "soo.gd", "s.id",  
    "t.ly", "rb.gy", "clck.ru", "qps.ru", "u.to",  
    "shorturl.at", "tiny.cc", "bc.vc", "po.st", "mcaf.ee",  
    "su.pr", "cli.gs", "budurl.com", "yourls.org", "polr.me",  
      
    # ===== خدمات متوسطة (30) =====  
    "adf.ly", "ouo.io", "sh.st", "adfoc.us", "j.mp",  
    "db.tt", "qr.ae", "qr.net", "cur.lv", "lnkd.in",  
    "fb.me", "youtu.be", "amzn.to", "amzn.com", "ebay.to",  
    "etsy.me", "spoti.fi", "open.spotify.com", "deezer.page.link", "music.apple.com",  
    "linkd.in", "pin.it", "redd.it", "tumblr.co", "wp.me",  
    "flip.it", "pocket.co", "instapaper.com", "readability.com", "getpocket.com",  
      
    # ===== خدمات إضافية (40) =====  
    "snip.ly", "sniply.io", "cuttly.com", "shortcm.li", "short.cm",  
    "t2mio.com", "urlzs.com", "v.ht", "zee.gl", "x.co",  
    "x.gd", "xurl.es", "y2u.be", "yep.it", "yoururl.com",  
    "zi.ma", "zi.mu", "zpr.io", "zws.im", "zzb.bz",  
    "1url.com", "2.gp", "2big.at", "2tu.us", "4sq.com",  
    "4url.cc", "6url.com", "7.ly", "a.co", "a.gd",  
    "a2a.me", "abbr.com", "ad.vu", "adb.ug", "adcraft.co",  
    "adcrun.ch", "adflav.com", "adjix.com", "adli.pw", "admy.link",  
}  
  
# =============================================================================  
# 🏢 100 علامة تجارية رسمية  
# =============================================================================  
OFFICIAL_BRANDS = {  
    # ===== البنوك السعودية (15) =====  
    "alrajhi": {  
        "domains": {"alrajhibank.com.sa", "alrajhi.com.sa", "alrajhibank.com"},  
        "keywords": ["alrajhi", "الراجحي", "مصرف الراجحي", "rajhi", "al rajhi"],  
        "name_ar": "مصرف الراجحي",  
        "category": "bank"  
    },  
    "alahli": {  
        "domains": {"alahli.com", "sab.com", "snb.com.sa", "snb.com"},  
        "keywords": ["الأهلي", "الاهلي", "alahli", "snb", "البنك الأهلي", "sab"],  
        "name_ar": "البنك الأهلي السعودي",  
        "category": "bank"  
    },  
    "alinma": {  
        "domains": {"alinma.com", "alinma.com.sa"},  
        "keywords": ["الإنماء", "الانماء", "alinma", "بنك الإنماء"],  
        "name_ar": "مصرف الإنماء",  
        "category": "bank"  
    },  
    "riyad_bank": {  
        "domains": {"riyadbank.com", "riyadbank.com.sa"},  
        "keywords": ["رياض", "riyadbank", "riyad bank", "بنك الرياض"],  
        "name_ar": "بنك الرياض",  
        "category": "bank"  
    },  
    "sabb": {  
        "domains": {"sabb.com", "sabb.com.sa"},  
        "keywords": ["ساب", "sabb", "بنك ساب"],  
        "name_ar": "بنك ساب",  
        "category": "bank"  
    },  
    "albilad": {  
        "domains": {"bankalbilad.com", "bankalbilad.com.sa"},  
        "keywords": ["البلاد", "albilad", "بنك البلاد", "bank albilad"],  
        "name_ar": "بنك البلاد",  
        "category": "bank"  
    },  
    "aljazira": {  
        "domains": {"baj.com.sa", "bankaljazira.com.sa"},  
        "keywords": ["الجزيرة", "aljazira", "بنك الجزيرة", "baj"],  
        "name_ar": "بنك الجزيرة",  
        "category": "bank"  
    },  
    "arabbank": {  
        "domains": {"arabbank.com.sa", "arabbank.com"},  
        "keywords": ["العربي", "arab bank", "البنك العربي"],  
        "name_ar": "البنك العربي",  
        "category": "bank"  
    },  
    "anb": {  
        "domains": {"anb.com.sa", "anb.com"},  
        "keywords": ["العربي الوطني", "anb", "arab national bank"],  
        "name_ar": "البنك العربي الوطني",  
        "category": "bank"  
    },  
    "saib": {  
        "domains": {"saib.com.sa"},  
        "keywords": ["السعودي للاستثمار", "saib", "saudi investment bank"],  
        "name_ar": "البنك السعودي للاستثمار",  
        "category": "bank"  
    },  
    "alfransi": {  
        "domains": {"alfransi.com.sa", "banquefrancaise.com.sa"},  
        "keywords": ["الفرنسي", "alfransi", "البنك السعودي الفرنسي"],  
        "name_ar": "البنك السعودي الفرنسي",  
        "category": "bank"  
    },  
    "gulf_bank": {  
        "domains": {"gulfbankksa.com"},  
        "keywords": ["الخليج", "gulf bank"],  
        "name_ar": "بنك الخليج",  
        "category": "bank"  
    },  
    "emirates_nbd": {  
        "domains": {"emiratesnbd.com.sa"},  
        "keywords": ["الإمارات دبي", "emirates nbd"],  
        "name_ar": "بنك الإمارات دبي الوطني",  
        "category": "bank"  
    },  
    "first_abu_dhabi": {  
        "domains": {"bankfab.com.sa"},  
        "keywords": ["أبوظبي الأول", "fab", "first abu dhabi"],  
        "name_ar": "بنك أبوظبي الأول",  
        "category": "bank"  
    },  
    "masraf_alarabi": {  
        "domains": {"masraf.com.sa"},  
        "keywords": ["مصرف العربي"],  
        "name_ar": "مصرف العربي",  
        "category": "bank"  
    },  
      
    # ===== خدمات الدفع السعودية (10) =====  
    "stcpay": {  
        "domains": {"stcpay.com.sa", "stcpay.app", "stc.com.sa"},  
        "keywords": ["stcpay", "stc-pay", "stc pay", "اس تي سي باي", "stc بي", "اس تي سي بي"],  
        "name_ar": "STC Pay",  
        "category": "payment"  
    },  
    "mada": {  
        "domains": {"mada.com.sa"},  
        "keywords": ["mada", "مدى", "شبكة مدى"],  
        "name_ar": "مدى",  
        "category": "payment"  
    },  
    "apple_pay_sa": {  
        "domains": {"apple.com/sa/apple-pay"},  
        "keywords": ["apple pay", "آبل باي"],  
        "name_ar": "Apple Pay السعودية",  
        "category": "payment"  
    },  
    "urpay": {  
        "domains": {"urpay.com.sa"},  
        "keywords": ["urpay", "يوربي"],  
        "name_ar": "URPay",  
        "category": "payment"  
    },  
    "bayan_pay": {  
        "domains": {"bayanpay.sa"},  
        "keywords": ["bayan pay", "بيان باي"],  
        "name_ar": "بيان باي",  
        "category": "payment"  
    },  
    "halala": {  
        "domains": {"halala.com.sa"},  
        "keywords": ["halala", "هللة"],  
        "name_ar": "هللة",  
        "category": "payment"  
    },  
    "sadad": {  
        "domains": {"sadad.com"},  
        "keywords": ["sadad", "سداد"],  
        "name_ar": "سداد",  
        "category": "payment"  
    },  
    "payfort": {  
        "domains": {"payfort.com"},  
        "keywords": ["payfort", "بيفورت"],  
        "name_ar": "PayFort",  
        "category": "payment"  
    },  
    "hyperpay": {  
        "domains": {"hyperpay.com"},  
        "keywords": ["hyperpay", "هايبر باي"],  
        "name_ar": "HyperPay",  
        "category": "payment"  
    },  
    "moyasar": {  
        "domains": {"moyasar.com"},  
        "keywords": ["moyasar", "ميسر"],  
        "name_ar": "ميسر",  
        "category": "payment"  
    },  
      
    # ===== الخدمات الحكومية السعودية (15) =====  
    "absher": {  
        "domains": {"absher.sa", "moi.gov.sa"},  
        "keywords": ["absher", "ابشر", "أبشر"],  
        "name_ar": "أبشر",  
        "category": "government"  
    },  
    "nafath": {  
        "domains": {"nafath.sa", "iam.gov.sa"},  
        "keywords": ["nafath", "نفاذ", "nفاذ"],  
        "name_ar": "نفاذ",  
        "category": "government"  
    },  
    "tawakkalna": {  
        "domains": {"tawakkalna.sa"},  
        "keywords": ["tawakkalna", "توكلنا", "tawakalna"],  
        "name_ar": "توكلنا",  
        "category": "government"  
    },  
    "najiz": {  
        "domains": {"najiz.sa", "moj.gov.sa"},  
        "keywords": ["najiz", "ناجز"],  
        "name_ar": "ناجز",  
        "category": "government"  
    },  
    "etimad": {  
        "domains": {"etimad.sa"},  
        "keywords": ["etimad", "اعتماد"],  
        "name_ar": "اعتماد",  
        "category": "government"  
    },  
    "muqeem": {  
        "domains": {"muqeem.sa"},  
        "keywords": ["muqeem", "مقيم"],  
        "name_ar": "مقيم",  
        "category": "government"  
    },  
    "qiwa": {  
        "domains": {"qiwa.sa"},  
        "keywords": ["qiwa", "قوى"],  
        "name_ar": "قوى",  
        "category": "government"  
    },  
    "seha": {  
        "domains": {"seha.sa", "moh.gov.sa"},  
        "keywords": ["seha", "صحة"],  
        "name_ar": "صحة",  
        "category": "government"  
    },  
    "balady": {  
        "domains": {"balady.gov.sa"},  
        "keywords": ["balady", "بلدي"],  
        "name_ar": "بلدي",  
        "category": "government"  
    },  
    "tamm": {  
        "domains": {"tamm.abudhabi"},  
        "keywords": ["tamm", "تم"],  
        "name_ar": "تم",  
        "category": "government"  
    },  
    "hrsd": {  
        "domains": {"hrsd.gov.sa"},  
        "keywords": ["hrsd", "الموارد البشرية"],  
        "name_ar": "وزارة الموارد البشرية",  
        "category": "government"  
    },  
    "gosi": {  
        "domains": {"gosi.gov.sa"},  
        "keywords": ["gosi", "التأمينات"],  
        "name_ar": "التأمينات الاجتماعية",  
        "category": "government"  
    },  
    "gazt": {  
        "domains": {"gazt.gov.sa", "zatca.gov.sa"},  
        "keywords": ["gazt", "zatca", "الزكاة", "الضريبة"],  
        "name_ar": "هيئة الزكاة والضريبة",  
        "category": "government"  
    },  
    "mc_gov": {  
        "domains": {"mc.gov.sa"},  
        "keywords": ["وزارة التجارة", "mc.gov"],  
        "name_ar": "وزارة التجارة",  
        "category": "government"  
    },  
    "sama": {  
        "domains": {"sama.gov.sa"},  
        "keywords": ["sama", "ساما", "البنك المركزي"],  
        "name_ar": "البنك المركزي السعودي",  
        "category": "government"  
    },  
      
    # ===== شركات الاتصالات (8) =====  
    "stc": {  
        "domains": {"stc.com.sa", "stc.sa"},  
        "keywords": ["stc", "اس تي سي", "الاتصالات السعودية"],  
        "name_ar": "STC",  
        "category": "telecom"  
    },  
    "mobily": {  
        "domains": {"mobily.com.sa", "mobily.sa"},  
        "keywords": ["mobily", "موبايلي"],  
        "name_ar": "موبايلي",  
        "category": "telecom"  
    },  
    "zain": {  
        "domains": {"zain.com", "sa.zain.com"},  
        "keywords": ["zain", "زين"],  
        "name_ar": "زين",  
        "category": "telecom"  
    },  
    "virgin_mobile": {  
        "domains": {"virginmobile.sa"},  
        "keywords": ["virgin", "فيرجن"],  
        "name_ar": "فيرجن موبايل",  
        "category": "telecom"  
    },  
    "lebara": {  
        "domains": {"lebara.sa"},  
        "keywords": ["lebara", "ليبارا"],  
        "name_ar": "ليبارا",  
        "category": "telecom"  
    },  
    "salam": {  
        "domains": {"salam.sa"},  
        "keywords": ["salam", "سلام"],  
        "name_ar": "سلام موبايل",  
        "category": "telecom"  
    },  
    "red_bull_mobile": {  
        "domains": {"redbullmobile.sa"},  
        "keywords": ["red bull mobile"],  
        "name_ar": "ريد بول موبايل",  
        "category": "telecom"  
    },  
    "friendi": {  
        "domains": {"friendi.com"},  
        "keywords": ["friendi", "فريندي"],  
        "name_ar": "فريندي",  
        "category": "telecom"  
    },  
      
    # ===== التجارة الإلكترونية السعودية (10) =====  
    "noon": {  
        "domains": {"noon.com", "noon.com.sa"},  
        "keywords": ["noon", "نون"],  
        "name_ar": "نون",  
        "category": "ecommerce"  
    },  
    "jarir": {  
        "domains": {"jarir.com", "jarir.com.sa"},  
        "keywords": ["jarir", "جرير"],  
        "name_ar": "جرير",  
        "category": "ecommerce"  
    },  
    "extra": {  
        "domains": {"extra.com", "extrastores.com"},  
        "keywords": ["extra", "اكسترا"],  
        "name_ar": "اكسترا",  
        "category": "ecommerce"  
    },  
    "namshi": {  
        "domains": {"namshi.com"},  
        "keywords": ["namshi", "نمشي"],  
        "name_ar": "نمشي",  
        "category": "ecommerce"  
    },  
    "ounass": {  
        "domains": {"ounass.com", "ounass.sa"},  
        "keywords": ["ounass", "اوناس"],  
        "name_ar": "أوناس",  
        "category": "ecommerce"  
    },  
    "sivvi": {  
        "domains": {"sivvi.com"},  
        "keywords": ["sivvi", "سيفي"],  
        "name_ar": "سيفي",  
        "category": "ecommerce"  
    },  
    "amazon_sa": {  
        "domains": {"amazon.sa"},  
        "keywords": ["amazon.sa", "امازون السعودية"],  
        "name_ar": "أمازون السعودية",  
        "category": "ecommerce"  
    },  
    "shein_sa": {  
        "domains": {"shein.com/sa"},  
        "keywords": ["shein", "شي ان"],  
        "name_ar": "شي إن",  
        "category": "ecommerce"  
    },  
    "trendyol_sa": {  
        "domains": {"trendyol.com"},  
        "keywords": ["trendyol", "ترينديول"],  
        "name_ar": "ترينديول",  
        "category": "ecommerce"  
    },  
    "fordeal": {  
        "domains": {"fordeal.com"},  
        "keywords": ["fordeal", "فورديل"],  
        "name_ar": "فورديل",  
        "category": "ecommerce"  
    },  
      
    # ===== شركات الطيران والسفر (10) =====  
    "saudia": {  
        "domains": {"saudia.com", "saudiairlines.com"},  
        "keywords": ["saudia", "السعودية", "الخطوط السعودية"],  
        "name_ar": "الخطوط السعودية",  
        "category": "travel"  
    },  
    "flynas": {  
        "domains": {"flynas.com"},  
        "keywords": ["flynas", "ناس", "طيران ناس"],  
        "name_ar": "طيران ناس",  
        "category": "travel"  
    },  
    "flyadeal": {  
        "domains": {"flyadeal.com"},  
        "keywords": ["flyadeal", "أديل", "طيران أديل"],  
        "name_ar": "طيران أديل",  
        "category": "travel"  
    },  
    "almosafer": {  
        "domains": {"almosafer.com"},  
        "keywords": ["almosafer", "المسافر"],  
        "name_ar": "المسافر",  
        "category": "travel"  
    },  
    "booking_sa": {  
        "domains": {"booking.com/sa"},  
        "keywords": ["booking", "بوكينج"],  
        "name_ar": "بوكينج",  
        "category": "travel"  
    },  
    "wego": {  
        "domains": {"wego.com", "wego.sa"},  
        "keywords": ["wego", "ويجو"],  
        "name_ar": "ويجو",  
        "category": "travel"  
    },  
    "tajawal": {  
        "domains": {"tajawal.com"},  
        "keywords": ["tajawal", "تجول"],  
        "name_ar": "تجول",  
        "category": "travel"  
    },  
    "cleartrip": {  
        "domains": {"cleartrip.sa"},  
        "keywords": ["cleartrip", "كلير تريب"],  
        "name_ar": "كلير تريب",  
        "category": "travel"  
    },  
    "flyin": {  
        "domains": {"flyin.com"},  
        "keywords": ["flyin", "فلاي إن"],  
        "name_ar": "فلاي إن",  
        "category": "travel"  
    },  
    "rehlat": {  
        "domains": {"rehlat.com.sa"},  
        "keywords": ["rehlat", "رحلات"],  
        "name_ar": "رحلات",  
        "category": "travel"  
    },  
      
    # ===== التوصيل والطعام (10) =====  
    "hungerstation": {  
        "domains": {"hungerstation.com"},  
        "keywords": ["hungerstation", "هنقرستيشن"],  
        "name_ar": "هنقرستيشن",  
        "category": "delivery"  
    },  
    "jahez": {  
        "domains": {"jahez.net", "jahez.com"},  
        "keywords": ["jahez", "جاهز"],  
        "name_ar": "جاهز",  
        "category": "delivery"  
    },  
    "toyou": {  
        "domains": {"toyou.io"},  
        "keywords": ["toyou", "تويو"],  
        "name_ar": "تويو",  
        "category": "delivery"  
    },  
    "mrsool": {  
        "domains": {"mrsool.co"},  
        "keywords": ["mrsool", "مرسول"],  
        "name_ar": "مرسول",  
        "category": "delivery"  
    },  
    "careem": {  
        "domains": {"careem.com"},  
        "keywords": ["careem", "كريم"],  
        "name_ar": "كريم",  
        "category": "delivery"  
    },  
    "uber_sa": {  
        "domains": {"uber.com/sa"},  
        "keywords": ["uber", "اوبر"],  
        "name_ar": "أوبر",  
        "category": "delivery"  
    },  
    "talabat": {  
        "domains": {"talabat.com"},  
        "keywords": ["talabat", "طلبات"],  
        "name_ar": "طلبات",  
        "category": "delivery"  
    },  
    "the_chefz": {  
        "domains": {"thechefz.com"},  
        "keywords": ["chefz", "ذا شفز"],  
        "name_ar": "ذا شفز",  
        "category": "delivery"  
    },  
    "cofe": {  
        "domains": {"cofeapp.com"},  
        "keywords": ["cofe", "كوفي"],  
        "name_ar": "كوفي",  
        "category": "delivery"  
    },  
    "nana": {  
        "domains": {"nana.sa"},  
        "keywords": ["nana", "نعناع"],  
        "name_ar": "نعناع",  
        "category": "delivery"  
    },  
      
    # ===== الشركات العالمية (22) =====  
    "apple": {  
        "domains": {"apple.com", "icloud.com", "apple.sa"},  
        "keywords": ["apple", "icloud", "آبل", "ابل", "آيفون", "iphone", "macbook"],  
        "name_ar": "Apple",  
        "category": "tech"  
    },  
    "google": {  
        "domains": {"google.com", "google.sa", "gmail.com"},  
        "keywords": ["google", "جوجل", "gmail", "يوتيوب"],  
        "name_ar": "Google",  
        "category": "tech"  
    },  
    "microsoft": {  
        "domains": {"microsoft.com", "outlook.com", "live.com", "office.com"},  
        "keywords": ["microsoft", "مايكروسوفت", "outlook", "office", "windows"],  
        "name_ar": "Microsoft",  
        "category": "tech"  
    },  
    "amazon": {  
        "domains": {"amazon.com", "amazon.ae"},  
        "keywords": ["amazon", "امازون", "أمازون"],  
        "name_ar": "Amazon",  
        "category": "ecommerce"  
    },  
    "facebook": {  
        "domains": {"facebook.com", "fb.com", "meta.com"},  
        "keywords": ["facebook", "فيسبوك", "فيس بوك", "meta"],  
        "name_ar": "Facebook",  
        "category": "social"  
    },  
    "instagram": {  
        "domains": {"instagram.com"},  
        "keywords": ["instagram", "انستقرام", "انستغرام"],  
        "name_ar": "Instagram",  
        "category": "social"  
    },  
    "whatsapp": {  
        "domains": {"whatsapp.com", "wa.me"},  
        "keywords": ["whatsapp", "واتساب", "واتس اب", "واتس"],  
        "name_ar": "WhatsApp",  
        "category": "social"  
    },  
    "twitter": {  
        "domains": {"twitter.com", "x.com"},  
        "keywords": ["twitter", "تويتر", "x.com"],  
        "name_ar": "Twitter/X",  
        "category": "social"  
    },  
    "snapchat": {  
        "domains": {"snapchat.com"},  
        "keywords": ["snapchat", "سناب", "سناب شات"],  
        "name_ar": "Snapchat",  
        "category": "social"  
    },  
    "tiktok": {  
        "domains": {"tiktok.com"},  
        "keywords": ["tiktok", "تيك توك", "تيكتوك"],  
        "name_ar": "TikTok",  
        "category": "social"  
    },  
    "linkedin": {  
        "domains": {"linkedin.com"},  
        "keywords": ["linkedin", "لينكد ان", "لينكدان"],  
        "name_ar": "LinkedIn",  
        "category": "social"  
    },  
    "paypal": {  
        "domains": {"paypal.com"},  
        "keywords": ["paypal", "باي بال", "بايبال"],  
        "name_ar": "PayPal",  
        "category": "payment"  
    },  
    "netflix": {  
        "domains": {"netflix.com"},  
        "keywords": ["netflix", "نتفلكس", "نيتفليكس"],  
        "name_ar": "Netflix",  
        "category": "entertainment"  
    },  
    "spotify": {  
        "domains": {"spotify.com"},  
        "keywords": ["spotify", "سبوتيفاي"],  
        "name_ar": "Spotify",  
        "category": "entertainment"  
    },  
    "youtube": {  
        "domains": {"youtube.com", "youtu.be"},  
        "keywords": ["youtube", "يوتيوب"],  
        "name_ar": "YouTube",  
        "category": "entertainment"  
    },  
    "zoom": {  
        "domains": {"zoom.us", "zoom.com"},  
        "keywords": ["zoom", "زوم"],  
        "name_ar": "Zoom",  
        "category": "tech"  
    },  
    "dropbox": {  
        "domains": {"dropbox.com"},  
        "keywords": ["dropbox", "دروبوكس"],  
        "name_ar": "Dropbox",  
        "category": "tech"  
    },  
    "adobe": {  
        "domains": {"adobe.com"},  
        "keywords": ["adobe", "أدوبي", "فوتوشوب"],  
        "name_ar": "Adobe",  
        "category": "tech"  
    },  
    "samsung": {  
        "domains": {"samsung.com", "samsung.com.sa"},  
        "keywords": ["samsung", "سامسونج", "سامسونغ"],  
        "name_ar": "Samsung",  
        "category": "tech"  
    },  
    "huawei": {  
        "domains": {"huawei.com", "consumer.huawei.com"},  
        "keywords": ["huawei", "هواوي"],  
        "name_ar": "Huawei",  
        "category": "tech"  
    },  
    "dhl": {  
        "domains": {"dhl.com", "dhl.com.sa"},  
        "keywords": ["dhl", "دي اتش ال"],  
        "name_ar": "DHL",  
        "category": "shipping"  
    },  
    "aramex": {  
        "domains": {"aramex.com"},  
        "keywords": ["aramex", "ارامكس"],  
        "name_ar": "Aramex",  
        "category": "shipping"  
    },  
}  
  
# =============================================================================  
# 🎯 أنماط التصيد والمحتوى المشبوه  
# =============================================================================  
PHISHING_URL_PATTERNS = [  
    # الخدمات الحكومية  
    r"absher[-_.]?(verify|login|update|sa|account|secure)",  
    r"nafath[-_.]?(login|verify|code|sa|auth|otp)",  
    r"tawakkalna[-_.]?(verify|update|login)",  
    r"najiz[-_.]?(login|verify|case)",  
    r"muqeem[-_.]?(login|verify|visa)",  
      
    # البنوك  
    r"(alrajhi|rajhi)[-_.]?(update|verify|login|secure|account)",  
    r"(alahli|ahli|snb)[-_.]?(update|verify|login|secure)",  
    r"(alinma|inma)[-_.]?(update|verify|login)",  
    r"(riyadbank|riyad)[-_.]?(update|verify|login)",  
    r"(sabb|sab)[-_.]?(update|verify|login)",  
      
    # خدمات الدفع  
    r"stc[-_.]?pay[-_.]?(login|verify|gift|prize|reward|update)",  
    r"mada[-_.]?(verify|update|card)",  
    r"apple[-_.]?pay[-_.]?(verify|sa)",  
      
    # أنماط عامة  
    r"(login|signin|verify|update|secure|account)[-_.]?(stc|absher|nafath|bank)",  
    r"(free|gift|prize|reward|winner)[-_.]?(stc|bank|iphone)",  
    r"(urgent|تحديث|تفعيل|تأكيد)[-_.]?(حساب|بيانات)",  
]  
  
SUSPICIOUS_PATTERNS = {  
    "credentials": [  
        "password", "كلمة المرور", "كلمة السر", "رقم سري",  
        "otp", "رمز التحقق", "رمز التأكيد", "كود التحقق",  
        "cvv", "cvc", "رقم البطاقة", "card number",  
        "iban", "آيبان", "رقم الحساب", "account number",  
        "pin", "الرقم السري", "رمز pin",  
        "username", "اسم المستخدم", "user id",  
        "social security", "الهوية الوطنية", "رقم الهوية",  
        "passport", "جواز السفر",  
    ],  
    "urgency": [  
        "urgent", "عاجل", "فوري", "immediately", "الآن", "حالاً",  
        "خلال 24 ساعة", "within 24 hours", "اليوم فقط", "today only",  
        "سينتهي", "expires", "آخر فرصة", "last chance",  
        "لا تفوت", "don't miss", "سارع", "hurry",  
        "محدود", "limited", "قبل فوات الأوان",  
    ],  
    "threat": [  
        "suspended", "موقوف", "معلق", "blocked", "محظور",  
        "تحذير", "warning", "تنبيه", "alert",  
        "سيتم إغلاق", "will be closed", "سيتم إيقاف", "will be suspended",  
        "مخالفة", "violation", "غير قانوني", "illegal",  
        "سيتم حذف", "will be deleted", "فقدان", "loss",  
        "تم اختراق", "hacked", "compromised",  
    ],  
    "lure": [  
        "congratulations", "مبروك", "تهانينا", "مبارك",  
        "prize", "جائزة", "هدية", "gift", "مكافأة", "reward",  
        "free", "مجاني", "مجاناً", "بدون مقابل",  
        "فزت", "won", "ربحت", "winner", "فائز",  
        "اختيارك", "selected", "تم اختيارك", "chosen",  
        "حصري", "exclusive", "خاص بك", "special offer",  
        "استرداد", "cashback", "استرجاع", "refund",  
    ],  
    "impersonation": [  
        "official", "رسمي", "الموقع الرسمي",  
        "verified", "موثق", "معتمد",  
        "support", "الدعم الفني", "خدمة العملاء",  
        "security team", "فريق الأمان",  
        "من البنك", "from bank", "من الشركة",  
    ],  
}  
  
  
# =============================================================================  
# 📊 MODELS  
# =============================================================================  
class RiskLevel(str, Enum):  
    SAFE = "safe"  
    SUSPICIOUS = "suspicious"  
    BLOCKED = "blocked"  
  
  
class ThreatCategory(str, Enum):  
    PHISHING = "phishing"  
    MALWARE = "malware"  
    SCAM = "scam"  
    BRAND_IMPERSONATION = "brand_impersonation"  
    SUSPICIOUS_DOMAIN = "suspicious_domain"  
    HARMFUL_CONTENT = "harmful_content"  
    UNKNOWN = "unknown"  
  
  
class ServiceResult(BaseModel):  
    service: str  
    available: bool  
    result: Optional[Dict[str, Any]] = None  
    error: Optional[str] = None  
  
  
class ThreatIndicator(BaseModel):  
    category: ThreatCategory  
    severity: Literal["low", "medium", "high", "critical"]  
    description: str  
  
  
class DomainInfo(BaseModel):  
    domain: str  
    effective_domain: str  
    is_free_hosting: bool  
    is_shortener: bool  
    is_official: bool  
    brand_match: Optional[str] = None  
  
  
class UrlAnalysisResponse(BaseModel):  
    url: str  
    status: RiskLevel  
    risk_score: int = Field(ge=0, le=100)  
    threat_category: ThreatCategory  
    domain_info: DomainInfo  
    indicators: List[ThreatIndicator]  
    recommendations: List[str]  
    services_results: List[ServiceResult]  
    ai_analysis: Optional[Dict[str, Any]] = None  
    analyzed_at: datetime  
    analysis_duration_ms: int  
  
  
class ContentAnalysisResponse(BaseModel):  
    content_length: int  
    status: RiskLevel  
    risk_score: int = Field(ge=0, le=100)  
    threat_category: ThreatCategory  
    indicators: List[ThreatIndicator]  
    detected_patterns: Dict[str, List[str]]  
    extracted_urls: List[str]  
    recommendations: List[str]  
    services_results: List[ServiceResult]  
    ai_analysis: Optional[Dict[str, Any]] = None  
    content_safety: Optional[Dict[str, Any]] = None  
    analyzed_at: datetime  
    analysis_duration_ms: int  
  
  
class ImageAnalysisResponse(BaseModel):  
    filename: str  
    file_size: int  
    status: RiskLevel  
    risk_score: int = Field(ge=0, le=100)  
    threat_category: ThreatCategory  
    extracted_text: Optional[str] = None  
    detected_brands: List[str]  
    detected_forms: bool  
    indicators: List[ThreatIndicator]  
    recommendations: List[str]  
    services_results: List[ServiceResult]  
    ai_analysis: Optional[Dict[str, Any]] = None  
    content_safety: Optional[Dict[str, Any]] = None  
    analyzed_at: datetime  
    analysis_duration_ms: int  
  
  
# =============================================================================  
# 🔒 SECURITY SERVICES  
# =============================================================================  
class SecurityServices:  
    """خدمات الأمان"""  
      
    @staticmethod
    def ai_analyze_sync(content: str, analysis_type: str, context: Dict[str, Any]) -> ServiceResult:
        """Claude AI Analysis via AWS Bedrock"""
        system_prompt = """أنت خبير أمن معلومات متخصص في الكشف عن الاحتيال الإلكتروني.
    مهمتك تحليل الروابط والمحتوى للكشف عن:
    1. التصيد الاحتيالي (Phishing)
    2. انتحال الهوية (Brand Impersonation)
    3. عمليات النصب والاحتيال
    4. الروابط الخبيثة
    
    ⚠️ مهم جداً: أرجع JSON نقي فقط بدون أي markdown أو ```json أو أي نص قبل أو بعد JSON.
    الصيغة المطلوبة:
    {
        "is_phishing": true/false,
        "risk_score": 0-100,
        "threat_category": "phishing|scam|brand_impersonation|malware|suspicious_domain|unknown",
        "confidence": 0-100,
        "indicators": [{"type": "نوع", "description": "وصف", "severity": "low|medium|high|critical"}],
        "targeted_brand": "اسم العلامة أو null",
        "explanation": "شرح بالعربية",
        "recommendations": ["توصية 1", "توصية 2"]
    }"""
    
        user_prompt = f"""حلل هذا {'الرابط' if analysis_type == 'url' else 'المحتوى'} للكشف عن الاحتيال:
    
    {content}
    
    معلومات إضافية:
    {json.dumps(context, ensure_ascii=False, indent=2)}"""
    
        try:
            client = Config.get_client()
    
            bedrock_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}]
            }
    
            response = client.invoke_model(
                modelId=Config.BEDROCK_MODEL_ID,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(bedrock_body)
            )
    
            response_body = json.loads(response["body"].read())
            response_text = response_body.get("content", [{}])[0].get("text", "")
    
            result = parse_claude_response(response_text)
            return ServiceResult(service="claude_ai", available=True, result=result)
    
        except Exception as e:
            return ServiceResult(service="claude_ai", available=True, error=str(e))

    @staticmethod
    async def ai_analyze(content: str, analysis_type: str, context: Dict[str, Any]) -> ServiceResult:
        """Claude AI Analysis - async wrapper"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            SecurityServices.ai_analyze_sync,
            content, analysis_type, context
        )

    @staticmethod
    async def google_safe_browsing(url: str) -> ServiceResult:  
        """Google Safe Browsing"""  
        api_key = Config.GOOGLE_SAFE_BROWSING_API_KEY  
        if not api_key:  
            return ServiceResult(service="google_safe_browsing", available=False)  
          
        try:  
            async with httpx.AsyncClient(timeout=10.0) as client:  
                response = await client.post(  
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",  
                    json={  
                        "client": {"clientId": "kashaf", "clientVersion": "4.0"},  
                        "threatInfo": {  
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],  
                            "platformTypes": ["ANY_PLATFORM"],  
                            "threatEntryTypes": ["URL"],  
                            "threatEntries": [{"url": url}]  
                        }  
                    }  
                )  
                data = response.json()  
                matches = data.get("matches", [])  
                return ServiceResult(  
                    service="google_safe_browsing",  
                    available=True,  
                    result={"is_threat": len(matches) > 0, "threat_types": [m.get("threatType") for m in matches]}  
                )  
        except Exception as e:  
            return ServiceResult(service="google_safe_browsing", available=True, error=str(e))  
      

    @staticmethod
      
    @staticmethod  
    async def google_web_risk(url: str) -> ServiceResult:  
        """Google Web Risk"""  
        api_key = Config.WEBRISK_API_KEY  
        if not api_key:  
            return ServiceResult(service="google_web_risk", available=False)  
          
        try:  
            async with httpx.AsyncClient(timeout=10.0) as client:  
                response = await client.get(  
                    "https://webrisk.googleapis.com/v1/uris:search",  
                    params={"uri": url, "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "key": api_key}  
                )  
                data = response.json()  
                threat = data.get("threat", {})  
                return ServiceResult(  
                    service="google_web_risk",  
                    available=True,  
                    result={"is_threat": bool(threat), "threat_types": threat.get("threatTypes", [])}  
                )  
        except Exception as e:  
            return ServiceResult(service="google_web_risk", available=True, error=str(e))  
      
    @staticmethod  
    async def whois_lookup(domain: str) -> ServiceResult:  
        """WHOIS Lookup"""  
        api_key = Config.WHOIS_API_KEY  
        if not api_key:  
            return ServiceResult(service="whois", available=False)  
          
        try:  
            async with httpx.AsyncClient(timeout=15.0) as client:  
                response = await client.get(  
                    "https://api.apilayer.com/whois/query",  
                    params={"domain": domain},  
                    headers={"apikey": api_key}  
                )  
                  
                if response.status_code == 200:  
                    data = response.json()  
                    creation = data.get("creation_date") or data.get("created")  
                    age_days = None  
                    is_new = False  
                      
                    if creation:  
                        try:  
                            created = datetime.strptime(creation.split("T")[0], "%Y-%m-%d")  
                            age_days = (datetime.now() - created).days  
                            is_new = age_days < 30  
                        except:  
                            pass  
                      
                    return ServiceResult(  
                        service="whois",  
                        available=True,  
                        result={"creation_date": creation, "domain_age_days": age_days, "is_newly_registered": is_new}  
                    )  
                      
                return ServiceResult(service="whois", available=True, error=f"HTTP {response.status_code}")  
        except Exception as e:  
            return ServiceResult(service="whois", available=True, error=str(e))  
      
    @staticmethod  
    async def azure_vision_ocr(image_bytes: bytes) -> ServiceResult:  
        """Azure Vision OCR"""  
        if not Config.AZURE_AI_VISION_KEY or not Config.AZURE_AI_VISION_BASE:  
            return ServiceResult(service="azure_vision", available=False)  
          
        try:  
            async with httpx.AsyncClient(timeout=30.0) as client:  
                response = await client.post(  
                    f"{Config.AZURE_AI_VISION_BASE}/vision/v3.2/ocr",  
                    params={"language": "ar", "detectOrientation": "true"},  
                    content=image_bytes,  
                    headers={  
                        "Content-Type": "application/octet-stream",  
                        "Ocp-Apim-Subscription-Key": Config.AZURE_AI_VISION_KEY  
                    }  
                )  
                  
                if response.status_code == 200:  
                    data = response.json()  
                    text_parts = []  
                    for region in data.get("regions", []):  
                        for line in region.get("lines", []):  
                            words = [w.get("text", "") for w in line.get("words", [])]  
                            text_parts.append(" ".join(words))  
                      
                    return ServiceResult(  
                        service="azure_vision",  
                        available=True,  
                        result={"extracted_text": "\n".join(text_parts)}  
                    )  
                      
                return ServiceResult(service="azure_vision", available=True, error=f"HTTP {response.status_code}")  
        except Exception as e:  
            return ServiceResult(service="azure_vision", available=True, error=str(e))  
      
    @staticmethod  
    async def azure_content_safety_text(text: str) -> ServiceResult:  
        """Azure Content Safety - Text Analysis"""  
        if not Config.AZURE_AI_CONTENT_SAFETY_KEY or not Config.AZURE_AI_CONTENT_SAFETY_BASE:  
            return ServiceResult(service="azure_content_safety", available=False)  
          
        try:  
            async with httpx.AsyncClient(timeout=30.0) as client:  
                response = await client.post(  
                    f"{Config.AZURE_AI_CONTENT_SAFETY_BASE}/contentsafety/text:analyze?api-version=2023-10-01",  
                    json={  
                        "text": text[:5000],  
                        "categories": ["Hate", "SelfHarm", "Sexual", "Violence"],  
                        "outputType": "FourSeverityLevels"  
                    },  
                    headers={  
                        "Content-Type": "application/json",  
                        "Ocp-Apim-Subscription-Key": Config.AZURE_AI_CONTENT_SAFETY_KEY  
                    }  
                )  
                  
                if response.status_code == 200:  
                    data = response.json()  
                    categories = data.get("categoriesAnalysis", [])  
                      
                    is_harmful = any(cat.get("severity", 0) >= 2 for cat in categories)  
                      
                    return ServiceResult(  
                        service="azure_content_safety",  
                        available=True,  
                        result={  
                            "is_harmful": is_harmful,  
                            "categories": {cat["category"]: cat["severity"] for cat in categories}  
                        }  
                    )  
                      
                return ServiceResult(service="azure_content_safety", available=True, error=f"HTTP {response.status_code}")  
        except Exception as e:  
            return ServiceResult(service="azure_content_safety", available=True, error=str(e))  
      
    @staticmethod  
    async def azure_content_safety_image(image_bytes: bytes) -> ServiceResult:  
        """Azure Content Safety - Image Analysis"""  
        if not Config.AZURE_AI_CONTENT_SAFETY_KEY or not Config.AZURE_AI_CONTENT_SAFETY_BASE:  
            return ServiceResult(service="azure_content_safety_image", available=False)  
          
        try:  
            import base64  
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')  
              
            async with httpx.AsyncClient(timeout=30.0) as client:  
                response = await client.post(  
                    f"{Config.AZURE_AI_CONTENT_SAFETY_BASE}/contentsafety/image:analyze?api-version=2023-10-01",  
                    json={  
                        "image": {"content": image_base64},  
                        "categories": ["Hate", "SelfHarm", "Sexual", "Violence"],  
                        "outputType": "FourSeverityLevels"  
                    },  
                    headers={  
                        "Content-Type": "application/json",  
                        "Ocp-Apim-Subscription-Key": Config.AZURE_AI_CONTENT_SAFETY_KEY  
                    }  
                )  
                  
                if response.status_code == 200:  
                    data = response.json()  
                    categories = data.get("categoriesAnalysis", [])  
                    is_harmful = any(cat.get("severity", 0) >= 2 for cat in categories)  
                      
                    return ServiceResult(  
                        service="azure_content_safety_image",  
                        available=True,  
                        result={  
                            "is_harmful": is_harmful,  
                            "categories": {cat["category"]: cat["severity"] for cat in categories}  
                        }  
                    )  
                      
                return ServiceResult(service="azure_content_safety_image", available=True, error=f"HTTP {response.status_code}")  
        except Exception as e:  
            return ServiceResult(service="azure_content_safety_image", available=True, error=str(e))  

def parse_claude_response(response_text: str) -> dict:
  """Parse Claude response - يتعامل مع markdown و JSON مقطوع"""
  # إزالة markdown fences
  clean = re.sub(r'```(?:json)?\s*', '', response_text).strip()
  clean = re.sub(r'```\s*$', '', clean).strip()

  # parse مباشر
  try:
      return json.loads(clean)
  except json.JSONDecodeError:
      pass

  # JSON مقطوع - نجد آخر } صالح
  start = clean.find("{")
  if start < 0:
      return {"raw_response": response_text}

  partial = clean[start:]
  last = partial.rfind("}")
  if last >= 0:
      try:
          return json.loads(partial[:last+1])
      except:
          pass

  # استخراج regex للحقول الأساسية (fallback لو JSON مقطوع فعلاً)
  result = {}
  patterns = [
      ("is_phishing",     r'"is_phishing"\s*:\s*(true|false)'),
      ("risk_score",      r'"risk_score"\s*:\s*(\d+)'),
      ("threat_category", r'"threat_category"\s*:\s*"([^"]+)"'),
      ("confidence",      r'"confidence"\s*:\s*(\d+)'),
      ("targeted_brand",  r'"targeted_brand"\s*:\s*"([^"]+)"'),
      ("explanation",     r'"explanation"\s*:\s*"([^"]{0,500})'),
  ]
  for field, pat in patterns:
      m = re.search(pat, partial)
      if m:
          val = m.group(1)
          if val == "true": val = True
          elif val == "false": val = False
          elif val.isdigit(): val = int(val)
          result[field] = val

  recs = re.findall(r'"((?:🚫|✅|⚠️|📱|🔐|🚨|👀)[^"]+)"', partial)
  if recs:
      result["recommendations"] = recs

  return result if result else {"raw_response": response_text}
  
# =============================================================================  
# 🔍 ANALYSIS ENGINE  
# =============================================================================  
class AnalysisEngine:  
    """محرك التحليل"""  
      
    @staticmethod  
    def get_effective_domain(url: str) -> str:  
        try:  
            parsed = urlparse(url)  
            host = parsed.netloc.lower()  
            if ":" in host:  
                host = host.split(":")[0]  
            if host.startswith("www."):  
                host = host[4:]  
              
            parts = host.split(".")  
            if len(parts) <= 2:  
                return host  
              
            if any(host.endswith(tld) for tld in [".com.sa", ".gov.sa", ".edu.sa", ".net.sa", ".org.sa"]):  
                return ".".join(parts[-3:])  
              
            return ".".join(parts[-2:])  
        except:  
            return ""  
      
    @staticmethod  
    def analyze_domain(url: str) -> DomainInfo:  
        parsed = urlparse(url)  
        host = parsed.netloc.lower()  
        if host.startswith("www."):  
            host = host[4:]  
          
        effective = AnalysisEngine.get_effective_domain(url)  
        is_free = effective in HIGH_RISK_DOMAINS  
        is_short = effective in LINK_SHORTENERS  
          
        brand_match = None  
        is_official = False  
          
        for brand_id, data in OFFICIAL_BRANDS.items():  
            if effective in data["domains"]:  
                brand_match = brand_id  
                is_official = True  
                break  
          
        return DomainInfo(  
            domain=host,  
            effective_domain=effective,  
            is_free_hosting=is_free,  
            is_shortener=is_short,  
            is_official=is_official,  
            brand_match=brand_match  
        )  
      
    @staticmethod  
    def check_phishing_patterns(url: str) -> Tuple[int, List[str]]:  
        url_lower = url.lower()  
        score = 0  
        matches = []  
          
        for pattern in PHISHING_URL_PATTERNS:  
            if re.search(pattern, url_lower):  
                score += 30  
                matches.append(f"نمط تصيد: {pattern[:40]}...")  
          
        return min(score, 60), matches  
      
    @staticmethod  
    def check_brand_impersonation(url: str, text: str = "") -> Tuple[bool, Optional[str], List[str]]:  
        combined = f"{url.lower()} {text.lower()}"  
        effective = AnalysisEngine.get_effective_domain(url)  
          
        for brand_id, data in OFFICIAL_BRANDS.items():  
            found = any(kw.lower() in combined for kw in data["keywords"])  
            if found and effective not in data["domains"]:  
                return True, brand_id, [f"انتحال محتمل لـ {data['name_ar']}"]  
          
        return False, None, []  
      
    @staticmethod  
    def extract_urls(text: str) -> List[str]:  
        pattern = r'https?://[^\s<>"{}|\\^`$$]+'  
        urls = re.findall(pattern, text)  
        return list(set([re.sub(r'[.,;:!?)]+$', '', u) for u in urls]))  
      
    @staticmethod  
    def analyze_content_patterns(text: str) -> Tuple[int, Dict[str, List[str]]]:  
        text_lower = text.lower()  
        score = 0  
        detected = defaultdict(list)  
          
        for category, patterns in SUSPICIOUS_PATTERNS.items():  
            for p in patterns:  
                if p.lower() in text_lower:  
                    detected[category].append(p)  
          
        if detected["credentials"]:  
            score += min(len(detected["credentials"]) * 10, 40)  
        if detected["urgency"]:  
            score += min(len(detected["urgency"]) * 7, 25)  
        if detected["threat"]:  
            score += min(len(detected["threat"]) * 10, 35)  
        if detected["lure"]:  
            score += min(len(detected["lure"]) * 5, 20)  
        if detected["impersonation"]:  
            score += min(len(detected["impersonation"]) * 8, 25)  
          
        return min(score, 85), dict(detected)  
      
    @staticmethod  
    def determine_status(score: int) -> RiskLevel:  
        if score >= 65:  
            return RiskLevel.BLOCKED  
        elif score >= 35:  
            return RiskLevel.SUSPICIOUS  
        return RiskLevel.SAFE  
      
    @staticmethod  
    def get_recommendations(status: RiskLevel, category: ThreatCategory) -> List[str]:  
        if status == RiskLevel.BLOCKED:  
            return [  
                "🚫 لا تضغط على هذا الرابط نهائياً",  
                "🔒 لا تدخل أي بيانات شخصية أو مالية",  
                "📱 تواصل مع الجهة الرسمية مباشرة للتحقق",  
                "🚨 أبلغ عن هذا الرابط للجهات المختصة (CERT-SA)",  
                "⚠️ احذف الرسالة فوراً وحذر الآخرين",  
            ]  
        elif status == RiskLevel.SUSPICIOUS:  
            return [  
                "⚠️ كن حذراً - هذا الرابط مشبوه",  
                "🔍 تحقق من الرابط عبر الموقع الرسمي",  
                "📞 اتصل بالجهة المعنية للتأكد",  
                "🛡️ لا تدخل بيانات حساسة حتى التأكد",  
            ]  
        return [  
            "✅ يبدو الرابط آمناً",  
            "👀 احرص دائماً على التحقق من الروابط",  
            "🔐 استخدم المصادقة الثنائية لحماية حساباتك",  
        ]  
  
  
# =============================================================================  
# 🎯 MAIN ANALYSIS FUNCTIONS  
# =============================================================================  
async def analyze_url_complete(url: str, deep_analysis: bool = True) -> UrlAnalysisResponse:  
    """تحليل شامل للرابط"""  
    start_time = datetime.now()  
      
    if not url.startswith(("http://", "https://")):  
        url = "https://" + url  
      
    domain_info = AnalysisEngine.analyze_domain(url)  
    indicators: List[ThreatIndicator] = []  
    services_results: List[ServiceResult] = []  
    score = 0  
      
    # تحليل الدومين  
    if domain_info.is_free_hosting:  
        score += 35  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.SUSPICIOUS_DOMAIN,  
            severity="medium",  
            description=f"استضافة مجانية عالية الخطورة: {domain_info.effective_domain}"  
        ))  
      
    if domain_info.is_shortener:  
        score += 30  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.SUSPICIOUS_DOMAIN,  
            severity="medium",  
            description=f"رابط مختصر يخفي الوجهة الحقيقية: {domain_info.effective_domain}"  
        ))  
      
    # أنماط التصيد  
    pattern_score, matches = AnalysisEngine.check_phishing_patterns(url)  
    score += pattern_score  
    for m in matches:  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.PHISHING,  
            severity="high",  
            description=m  
        ))  
      
    # انتحال العلامات  
    is_impersonation, brand, _ = AnalysisEngine.check_brand_impersonation(url)  
    if is_impersonation:  
        score += 45  
        brand_name = OFFICIAL_BRANDS.get(brand, {}).get("name_ar", brand)  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.BRAND_IMPERSONATION,  
            severity="critical",  
            description=f"انتحال محتمل لعلامة {brand_name}"  
        ))  
      
    # Google Safe Browsing  
    gsb = await SecurityServices.google_safe_browsing(url)  
    services_results.append(gsb)  
    if gsb.result and gsb.result.get("is_threat"):  
        score += 50  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.MALWARE,  
            severity="critical",  
            description="تهديد مؤكد من Google Safe Browsing"  
        ))  
      
    # Google Web Risk  
    wr = await SecurityServices.google_web_risk(url)  
    services_results.append(wr)  
    if wr.result and wr.result.get("is_threat"):  
        score += 40  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.MALWARE,  
            severity="critical",  
            description="تهديد من Google Web Risk"  
        ))  
      
    # WHOIS  
    whois = await SecurityServices.whois_lookup(domain_info.effective_domain)  
    services_results.append(whois)  
    if whois.result and whois.result.get("is_newly_registered"):  
        score += 25  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.SUSPICIOUS_DOMAIN,  
            severity="medium",  
            description=f"دومين مسجل حديثاً (أقل من 30 يوم)"  
        ))  
      
    # AI Analysis  
    ai_result = None  
    if deep_analysis:  
        context = {  
            "domain": domain_info.domain,  
            "is_free_hosting": domain_info.is_free_hosting,  
            "is_shortener": domain_info.is_shortener,  
            "current_indicators": [i.description for i in indicators[:5]]  
        }  
        ai_service = await SecurityServices.ai_analyze(url, "url", context)  
        services_results.append(ai_service)  
          
        if ai_service.result and not ai_service.error:  
            ai_result = ai_service.result  
            if ai_result.get("is_phishing"):  
                claude_score = ai_result.get("risk_score", 0)
                score = max(score + (claude_score // 2), claude_score)
      
    final_score = min(100, score)  
    status = AnalysisEngine.determine_status(final_score)  
      
    # تحديد الفئة - Claude أولاً
    category = ThreatCategory.UNKNOWN
    if ai_result and not ai_result.get("raw_response"):
        _cat_map = {
            "phishing": ThreatCategory.PHISHING,
            "scam": ThreatCategory.SCAM,
            "brand_impersonation": ThreatCategory.BRAND_IMPERSONATION,
            "malware": ThreatCategory.MALWARE,
            "harmful_content": ThreatCategory.HARMFUL_CONTENT,
            "suspicious_domain": ThreatCategory.SUSPICIOUS_DOMAIN,
        }
        _tc = ai_result.get("threat_category", "").lower()
        if _tc in _cat_map:
            category = _cat_map[_tc]
    if category == ThreatCategory.UNKNOWN:
        if is_impersonation:
            category = ThreatCategory.BRAND_IMPERSONATION
        elif gsb.result and gsb.result.get("is_threat"):
            category = ThreatCategory.MALWARE
        elif matches:
            category = ThreatCategory.PHISHING
        elif domain_info.is_free_hosting:
            category = ThreatCategory.SUSPICIOUS_DOMAIN

    if ai_result and not ai_result.get("raw_response") and isinstance(ai_result.get("recommendations"), list):
        recommendations = ai_result["recommendations"]
    else:
        recommendations = AnalysisEngine.get_recommendations(status, category)
    duration = int((datetime.now() - start_time).total_seconds() * 1000)  
      
    return UrlAnalysisResponse(  
        url=url,  
        status=status,  
        risk_score=final_score,  
        threat_category=category,  
        domain_info=domain_info,  
        indicators=indicators,  
        recommendations=recommendations,  
        services_results=services_results,  
        ai_analysis=ai_result,  
        analyzed_at=datetime.now(),  
        analysis_duration_ms=duration  
    )  
  
  
async def analyze_content_complete(content: str) -> ContentAnalysisResponse:  
    
    """تحليل المحتوى"""  
    start_time = datetime.now()  
    indicators: List[ThreatIndicator] = []  
    services_results: List[ServiceResult] = []  
      
    # تحليل الأنماط  
    score, patterns = AnalysisEngine.analyze_content_patterns(content)  
      
    if patterns.get("credentials"):  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.PHISHING,  
            severity="high",  
            description=f"يطلب بيانات حساسة: {', '.join(patterns['credentials'][:3])}"  
        ))  
      
    if patterns.get("urgency"):  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.SCAM,  
            severity="medium",  
            description="رسائل استعجال لدفعك للتصرف بسرعة"  
        ))  
      
    if patterns.get("threat"):  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.SCAM,  
            severity="high",  
            description="تهديدات بإغلاق الحساب أو عقوبات"  
        ))  
      
    if patterns.get("lure"):  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.SCAM,  
            severity="medium",  
            description="إغراءات بجوائز أو هدايا مجانية"  
        ))  
      
    # انتحال العلامات  
    is_imp, brand, _ = AnalysisEngine.check_brand_impersonation("", content)  
    if is_imp:  
        score += 25  
        indicators.append(ThreatIndicator(  
            category=ThreatCategory.BRAND_IMPERSONATION,  
            severity="high",  
            description=f"ذكر علامة تجارية: {OFFICIAL_BRANDS.get(brand, {}).get('name_ar', brand)}"  
        ))  
      
    # استخراج الروابط  
    urls = AnalysisEngine.extract_urls(content)  
      
    # Content Safety  
    content_safety_result = None  
    cs = await SecurityServices.azure_content_safety_text(content)  
    services_results.append(cs)  
    if cs.result and not cs.error:  
        content_safety_result = cs.result  
        if cs.result.get("is_harmful"):  
            score += 30  
            indicators.append(ThreatIndicator(  
                category=ThreatCategory.HARMFUL_CONTENT,  
                severity="high",  
                description="محتوى ضار تم اكتشافه"  
            ))  
      
    # ✅ AI Analysis - Claude يحدد كل شيء  
    ai_result = None  
    final_status = "safe"  
    final_score = score  
    final_category = ThreatCategory.UNKNOWN  
    recommendations = []  
      
    # تجهيز السياق الكامل لـ Claude  
    context = {  
        "patterns": patterns,  
        "urls_count": len(urls),  
        "urls": urls[:5],  # أول 5 روابط  
        "initial_score": score,  
        "brand_impersonation": is_imp,  
        "brand_name": OFFICIAL_BRANDS.get(brand, {}).get('name_ar', brand) if is_imp else None,  
        "indicators": [  
            {  
                "category": ind.category.value,  
                "severity": ind.severity,  
                "description": ind.description  
            } for ind in indicators  
        ],  
        "content_safety": content_safety_result  
    }  
      
    ai_service = await SecurityServices.ai_analyze(content[:5000], "content", context)  
    services_results.append(ai_service)  
      
    if ai_service.result and not ai_service.error:  
        ai_result = ai_service.result  
          
        # ✅ Claude يحدد حالة الخطورة  
        if "risk_level" in ai_result:  
            final_status = ai_result["risk_level"]  # safe, suspicious, dangerous, critical  
          
        # ✅ Claude يحدد درجة الخطورة النهائية  
        if "final_risk_score" in ai_result:  
            final_score = min(100, ai_result["final_risk_score"])  
          
        # ✅ Claude يحدد التصنيف  
        if "threat_category" in ai_result:  
            category_map = {  
                "phishing": ThreatCategory.PHISHING,  
                "scam": ThreatCategory.SCAM,  
                "brand_impersonation": ThreatCategory.BRAND_IMPERSONATION,  
                "harmful_content": ThreatCategory.HARMFUL_CONTENT,  
                "malware": ThreatCategory.MALWARE,  
                "spam": ThreatCategory.SCAM,  
                "safe": ThreatCategory.UNKNOWN  
            }  
            final_category = category_map.get(  
                ai_result["threat_category"].lower(),   
                ThreatCategory.UNKNOWN  
            )  
          
        # ✅ Claude يعطي التوصيات  
        if "recommendations" in ai_result and isinstance(ai_result["recommendations"], list):  
            recommendations = ai_result["recommendations"]  
      
    # إذا فشل Claude، استخدم النظام القديم كـ fallback  
    if not recommendations:  
        final_status = AnalysisEngine.determine_status(final_score)  
        if final_category == ThreatCategory.UNKNOWN:  
            if is_imp:  
                final_category = ThreatCategory.BRAND_IMPERSONATION  
            elif patterns.get("credentials"):  
                final_category = ThreatCategory.PHISHING  
            elif patterns.get("threat") or patterns.get("lure"):  
                final_category = ThreatCategory.SCAM  
            elif content_safety_result and content_safety_result.get("is_harmful"):  
                final_category = ThreatCategory.HARMFUL_CONTENT  
          
        recommendations = AnalysisEngine.get_recommendations(final_status, final_category)  
      
    duration = int((datetime.now() - start_time).total_seconds() * 1000)  
      
    return ContentAnalysisResponse(  
        content_length=len(content),  
        status=final_status,  
        risk_score=final_score,  
        threat_category=final_category,  
        indicators=indicators,  
        detected_patterns=patterns,  
        extracted_urls=urls,  
        recommendations=recommendations,  
        services_results=services_results,  
        ai_analysis=ai_result,  
        content_safety=content_safety_result,  
        analyzed_at=datetime.now(),  
        analysis_duration_ms=duration  
    )  
  
  
async def analyze_image_complete(image_bytes: bytes, filename: str) -> ImageAnalysisResponse:  
    """تحليل الصورة"""  
    start_time = datetime.now()  
    indicators: List[ThreatIndicator] = []  
    services_results: List[ServiceResult] = []  
    detected_brands: List[str] = []  
    detected_forms = False  
    extracted_text = None  
    score = 0  
      
    # OCR  
    vision = await SecurityServices.azure_vision_ocr(image_bytes)  
    services_results.append(vision)  
      
    if vision.result and not vision.error:  
        extracted_text = vision.result.get("extracted_text", "")  
          
        if extracted_text:  
            text_lower = extracted_text.lower()  
              
            # البحث عن علامات  
            for brand_id, data in OFFICIAL_BRANDS.items():  
                if any(kw.lower() in text_lower for kw in data["keywords"]):  
                    detected_brands.append(data["name_ar"])  
                    score += 15  
              
            # البحث عن نماذج  
            login_words = ["login", "password", "تسجيل", "كلمة المرور", "دخول", "sign in", "username"]  
            if any(w in text_lower for w in login_words):  
                detected_forms = True  
                score += 25  
                indicators.append(ThreatIndicator(  
                    category=ThreatCategory.PHISHING,  
                    severity="high",  
                    description="نموذج تسجيل دخول مكتشف في الصورة"  
                ))  
              
            if detected_brands and detected_forms:  
                score += 35  
                indicators.append(ThreatIndicator(  
                    category=ThreatCategory.BRAND_IMPERSONATION,  
                    severity="critical",  
                    description=f"صفحة تصيد محتملة تنتحل: {', '.join(detected_brands[:3])}"  
                ))  
      
    # Content Safety للصورة  
    content_safety_result = None  
    cs_img = await SecurityServices.azure_content_safety_image(image_bytes)  
    services_results.append(cs_img)  
      
    if cs_img.result and not cs_img.error:  
        content_safety_result = cs_img.result  
        if cs_img.result.get("is_harmful"):  
            score += 30  
            indicators.append(ThreatIndicator(  
                category=ThreatCategory.HARMFUL_CONTENT,  
                severity="high",  
                description="محتوى ضار في الصورة"  
            ))  
      
    # ✅ AI Analysis - Claude يحدد كل شيء  
    ai_result = None  
    final_status = "safe"  
    final_score = score  
    final_category = ThreatCategory.UNKNOWN  
    recommendations = []  
      
    if extracted_text:  
        # تجهيز السياق الكامل لـ Claude  
        context = {  
            "brands": detected_brands,  
            "forms": detected_forms,  
            "initial_score": score,  
            "indicators": [  
                {  
                    "category": ind.category.value,  
                    "severity": ind.severity,  
                    "description": ind.description  
                } for ind in indicators  
            ],  
            "content_safety": content_safety_result,  
            "analysis_type": "image_with_text"  
        }  
          
        ai_service = await SecurityServices.ai_analyze(extracted_text, "image", context)  
        services_results.append(ai_service)  
          
        if ai_service.result and not ai_service.error:  
            ai_result = ai_service.result  
              
            # ✅ Claude يحدد حالة الخطورة  
            if "risk_level" in ai_result:  
                final_status = ai_result["risk_level"]  
              
            # ✅ Claude يحدد درجة الخطورة النهائية  
            if "final_risk_score" in ai_result:  
                final_score = min(100, ai_result["final_risk_score"])  
              
            # ✅ Claude يحدد التصنيف  
            if "threat_category" in ai_result:  
                category_map = {  
                    "phishing": ThreatCategory.PHISHING,  
                    "scam": ThreatCategory.SCAM,  
                    "brand_impersonation": ThreatCategory.BRAND_IMPERSONATION,  
                    "harmful_content": ThreatCategory.HARMFUL_CONTENT,  
                    "malware": ThreatCategory.MALWARE,  
                    "spam": ThreatCategory.SCAM,  
                    "safe": ThreatCategory.UNKNOWN  
                }  
                final_category = category_map.get(  
                    ai_result["threat_category"].lower(),   
                    ThreatCategory.UNKNOWN  
                )  
              
            # ✅ Claude يعطي التوصيات  
            if "recommendations" in ai_result and isinstance(ai_result["recommendations"], list):  
                recommendations = ai_result["recommendations"]  
      
    # إذا فشل Claude، استخدم النظام القديم كـ fallback  
    if not recommendations:  
        final_status = AnalysisEngine.determine_status(final_score)  
        if final_category == ThreatCategory.UNKNOWN:  
            if detected_brands and detected_forms:  
                final_category = ThreatCategory.BRAND_IMPERSONATION  
            elif detected_forms:  
                final_category = ThreatCategory.PHISHING  
            elif content_safety_result and content_safety_result.get("is_harmful"):  
                final_category = ThreatCategory.HARMFUL_CONTENT  
          
        recommendations = AnalysisEngine.get_recommendations(final_status, final_category)  
      
    duration = int((datetime.now() - start_time).total_seconds() * 1000)  
      
    return ImageAnalysisResponse(  
        filename=filename,  
        file_size=len(image_bytes),  
        status=final_status,  
        risk_score=final_score,  
        threat_category=final_category,  
        extracted_text=extracted_text,  
        detected_brands=list(set(detected_brands)),  
        detected_forms=detected_forms,  
        indicators=indicators,  
        recommendations=recommendations,  
        services_results=services_results,  
        ai_analysis=ai_result,  
        content_safety=content_safety_result,  
        analyzed_at=datetime.now(),  
        analysis_duration_ms=duration  
    )  
# =============================================================================  
# 🌐 API ENDPOINTS  
# =============================================================================  
@app.get("/")  
async def root():  
    """الصفحة الرئيسية"""  
    return {  
        "name": "🛡️ Kashaf Ultimate Phishing Analyzer",  
        "version": "4.0.0",  
        "description": "نظام كشف متكامل للاحتيال والتصيد الإلكتروني",  
        "database": {  
            "high_risk_domains": len(HIGH_RISK_DOMAINS),  
            "link_shorteners": len(LINK_SHORTENERS),  
            "official_brands": len(OFFICIAL_BRANDS),  
        },  
        "ai": f"Claude ({Config.BEDROCK_MODEL_ID})",  
        "endpoints": {  
            "analyze_url": "GET /analyze/url?url=<URL>",  
            "analyze_content": "GET /analyze/content?text=<TEXT>",  
            "analyze_image": "POST /analyze/image",  
            "health": "GET /health",  
            "stats": "GET /stats",  
        }  
    }  
  
  
@app.get("/analyze/url", response_model=UrlAnalysisResponse)  
async def analyze_url_endpoint(  
    url: str = Query(..., description="الرابط المراد تحليله"),  
    deep_analysis: bool = Query(True, description="تحليل عميق بالذكاء الاصطناعي")  
):  
    """تحليل رابط للكشف عن التصيد والاحتيال"""  
    if not url:  
        raise HTTPException(400, "الرجاء إدخال رابط")  
    return await analyze_url_complete(url, deep_analysis)  
  
  
@app.get("/analyze/content", response_model=ContentAnalysisResponse)  
async def analyze_content_endpoint(  
    text: str = Query(..., max_length=50000, description="النص المراد تحليله")  
):  
    """تحليل محتوى نصي (رسائل، إيميلات)"""  
    if not text:  
        raise HTTPException(400, "الرجاء إدخال نص")  
    return await analyze_content_complete(text)  
  
  
@app.post("/analyze/image", response_model=ImageAnalysisResponse)  
async def analyze_image_endpoint(file: UploadFile = File(...)):  
    """تحليل صورة (سكرين شوت لصفحة مشبوهة)"""  
    allowed = ["image/jpeg", "image/png", "image/gif", "image/webp"]  
    if file.content_type not in allowed:  
        raise HTTPException(400, "نوع الملف غير مدعوم. الأنواع المدعومة: JPEG, PNG, GIF, WebP")  
      
    contents = await file.read()  
    if len(contents) > 10 * 1024 * 1024:  
        raise HTTPException(400, "حجم الملف أكبر من 10MB")  
      
    return await analyze_image_complete(contents, file.filename or "image")  
  
  
@app.get("/health")  
async def health():  
    """فحص صحة الخدمة"""  
    return {  
        "status": "healthy",  
        "timestamp": datetime.now().isoformat(),  
        "version": "4.0.0",  
        "services": Config.get_active_services()  
    }  
  
  
@app.get("/stats")  
async def stats():  
    """إحصائيات قاعدة البيانات"""  
    return {  
        "database_stats": {  
            "high_risk_domains": len(HIGH_RISK_DOMAINS),  
            "link_shorteners": len(LINK_SHORTENERS),  
            "official_brands": len(OFFICIAL_BRANDS),  
            "phishing_patterns": len(PHISHING_URL_PATTERNS),  
            "suspicious_pattern_categories": len(SUSPICIOUS_PATTERNS),  
        },  
        "brands_by_category": {  
            category: len([b for b, d in OFFICIAL_BRANDS.items() if d.get("category") == category])  
            for category in set(d.get("category", "other") for d in OFFICIAL_BRANDS.values())  
        },  
        "services": Config.get_active_services(),  
    }  
  
  
# =============================================================================  
# 🚀 RUN  
# =============================================================================  
if __name__ == "__main__":
    import uvicorn

    print(f"""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║     🛡️  Kashaf Ultimate Phishing Analyzer v4.0  🛡️                   ║
    ║                                                                       ║
    ╠═══════════════════════════════════════════════════════════════════════╣
    ║                                                                       ║
    ║  📊 قاعدة البيانات:                                                   ║
    ║     • {len(HIGH_RISK_DOMAINS):,} دومين خطر                                          ║
    ║     • {len(LINK_SHORTENERS):,} خدمة اختصار                                         ║
    ║     • {len(OFFICIAL_BRANDS):,} علامة تجارية                                        ║
    ║                                                                       ║
    ║  🤖 AI: AWS Bedrock + Claude ({Config.BEDROCK_MODEL_ID})
    ║  🔒 Content Safety: Azure AI Content Safety                           ║
    ║                                                                       ║
    ║  📡 Docs: http://localhost:8000/docs                                  ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)

    uvicorn.run("main:app", host="0.0.0.0", port=10000, reload=True)