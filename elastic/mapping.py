# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

mapping = {
    "malice": {
        "mappings": {
            "samples": {
                "_all": {"enabled": True},
                "properties": {
                    "file": {
                        "properties": {
                            "md5": {"type": "text"},
                            "mime": {"type": "keyword"},
                            "name": {"type": "text"},
                            "path": {"type": "text"},
                            "sha1": {"type": "text"},
                            "sha256": {"type": "text"},
                            "sha512": {"type": "text"},
                            "size": {"type": "text"},
                        }
                    },
                    "plugins": {
                        "properties": {
                            "archive": {"type": "object"},
                            "av": {
                                "properties": {
                                    "avg": {
                                        "properties": {
                                            "database": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "result": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "bitdefender": {
                                        "properties": {
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "result": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "clamav": {
                                        "properties": {
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "known": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "result": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "comodo": {
                                        "properties": {
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "result": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "f-prot": {
                                        "properties": {
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "result": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "fsecure": {
                                        "properties": {
                                            "database": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "results": {
                                                "properties": {
                                                    "aquarius": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "fse": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                }
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "sophos": {
                                        "properties": {
                                            "database": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "engine": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "infected": {"type": "boolean"},
                                            "result": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "updated": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    },
                                    "yara": {
                                        "properties": {
                                            "Matches": {
                                                "properties": {
                                                    "Meta": {
                                                        "properties": {
                                                            "author": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "description": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "ep_only": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "method": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                        }
                                                    },
                                                    "Namespace": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "Rule": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "Strings": {
                                                        "properties": {
                                                            "Data": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Name": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Offset": {"type": "long"},
                                                        }
                                                    },
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "document": {"type": "object"},
                            "exe": {"type": "object"},
                            "intel": {
                                "properties": {
                                    "nsrl": {
                                        "properties": {"Found": {"type": "boolean"}}
                                    },
                                    "shadow-server": {
                                        "properties": {
                                            "found": {"type": "boolean"},
                                            "sandbox": {
                                                "properties": {
                                                    "antivirus": {
                                                        "properties": {
                                                            "AVG": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "AntiVir": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Avira": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "DrWeb": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Eset": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "F-Secure": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "FSecure": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Ikarus": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Kaspersky": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "McAfee": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "NOD32": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Norman": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "QuickHeal": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Sophos": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Sunbelt": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "Symantec": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                        }
                                                    },
                                                    "metadata": {
                                                        "properties": {
                                                            "first_seen": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "last_seen": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "md5": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "sha1": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "ssdeep": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                            "type": {
                                                                "type": "text",
                                                                "fields": {
                                                                    "keyword": {
                                                                        "type": "keyword",
                                                                        "ignore_above": 256,
                                                                    }
                                                                },
                                                            },
                                                        }
                                                    },
                                                }
                                            },
                                        }
                                    },
                                    "virustotal": {
                                        "type": "object",
                                        "dynamic": "false",
                                    },
                                }
                            },
                            "metadata": {
                                "properties": {
                                    "fileinfo": {
                                        "properties": {
                                            "exiftool": {
                                                "properties": {
                                                    "CharacterSet": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "CodeSize": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "CompanyName": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "EntryPoint": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "ExifToolVersionNumber": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileDescription": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileFlags": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileFlagsMask": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileOS": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileSize": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileSubtype": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileType": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileTypeExtension": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileVersion": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "FileVersionNumber": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "ImageVersion": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "InitializedDataSize": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "InternalName": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "LanguageCode": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "LegalCopyright": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "LegalTrademarks": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "LinkerVersion": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "MIMEType": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "MachineType": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "OSVersion": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "ObjectFileType": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "OriginalFileName": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "PEType": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "ProductName": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "ProductVersion": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "ProductVersionNumber": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "Subsystem": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "SubsystemVersion": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "UninitializedDataSize": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                }
                                            },
                                            "magic": {
                                                "properties": {
                                                    "description": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                    "mime": {
                                                        "type": "text",
                                                        "fields": {
                                                            "keyword": {
                                                                "type": "keyword",
                                                                "ignore_above": 256,
                                                            }
                                                        },
                                                    },
                                                }
                                            },
                                            "ssdeep": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                            "trid": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            },
                                        }
                                    }
                                }
                            },
                            "pe": {
                                "properties": {
                                    "floss": {
                                        "properties": {
                                            "ascii": {
                                                "type": "text",
                                                "fields": {
                                                    "keyword": {
                                                        "type": "keyword",
                                                        "ignore_above": 256,
                                                    }
                                                },
                                            }
                                        }
                                    }
                                }
                            },
                        }
                    },
                    "scan_date": {"type": "date"},
                },
            },
            "_default_": {"_all": {"enabled": True}},
        }
    }
}
