{% if flag?(:freebsd) %}
  @[Link("pkg")]
  lib LibPkg
    # -------------------------------------------------------------------
    # Opaque handle types
    # -------------------------------------------------------------------
    type PkgHandle = Void*
    type PkgDb = Void*
    type PkgDbIt = Void*
    type PkgDep = Void*
    type PkgFile = Void*
    type PkgDir = Void*
    type PkgOption = Void*
    type PkgConflict = Void*
    type PkgCfgFile = Void*
    type PkgRepo = Void*
    type PkgKvlist = Void*
    type PkgStringlist = Void*
    type PkgKvlistIt = Void*
    type PkgStringlistIt = Void*

    # -------------------------------------------------------------------
    # pkg_el — NOT opaque; layout is public in pkg.h.
    #
    # C definition:
    #   typedef enum { PKG_KVLIST=1, PKG_STRINGLIST, PKG_STR, PKG_INTEGER,
    #                  PKG_BOOLEAN } pkg_el_t;
    #   struct pkg_el {
    #     union { struct pkg_kvlist *kvlist; struct pkg_stringlist *stringlist;
    #             const char *string; int64_t integer; bool boolean; };
    #     pkg_el_t type;   // uint32_t
    #   };
    #
    # Crystal cannot model anonymous unions, so we represent the union as
    # an 8-byte payload (pointer-width on amd64) and let callers cast it.
    # -------------------------------------------------------------------
    enum PkgElT : UInt32
      KvList     = 1
      StringList = 2
      Str        = 3
      Integer    = 4
      Boolean    = 5
    end

    struct PkgEl
      payload : UInt8[8] # union: largest member is 8 bytes on amd64
      type : PkgElT      # UInt32 discriminant
    end

    # -------------------------------------------------------------------
    # Enumerations
    # -------------------------------------------------------------------

    enum PkgErrorT : Int32
      Ok           =  0
      End          =  1
      Warn         =  2
      Fatal        =  3
      Required     =  4
      Installed    =  5
      Dependency   =  6
      Locked       =  7
      EnoDB        =  8
      UpToDate     =  9
      Unknown      = 10
      RepoSchema   = 11
      ENoAccess    = 12
      Insecure     = 13
      Conflict     = 14
      Again        = 15
      NotInstalled = 16
      Vital        = 17
      Exist        = 18
      Cancel       = 19
      NoNetwork    = 20
      ENoEnt       = 21
      OpNotSupp    = 22
      NoCompat32   = 23
    end

    enum MatchT : Int32
      All      = 0
      Exact    = 1
      Glob     = 2
      Regex    = 3
      Internal = 4
    end

    enum PkgdbLockT : Int32
      Readonly  = 0
      Advisory  = 1
      Exclusive = 2
    end

    enum PkgdbT : Int32
      Default         = 0
      Remote          = 1
      MaybeRemote     = 2
      DefaultReadonly = 3
    end

    enum PkgT : UInt32
      None           =  0
      File           =  1
      Stream         =  2
      Remote         =  4
      Installed      =  8
      OldFile        = 16
      GroupRemote    = 32
      GroupInstalled = 64
    end

    enum PkgAttr : UInt32
      Origin         =  1
      Name           =  2
      Version        =  3
      Comment        =  4
      Desc           =  5
      Mtree          =  6
      Message        =  7
      Arch           =  8
      Abi            =  9
      Maintainer     = 10
      Www            = 11
      Prefix         = 12
      Repopath       = 13
      Cksum          = 14
      OldVersion     = 15
      Reponame       = 16
      Repourl        = 17
      Digest         = 18
      Reason         = 19
      Flatsize       = 20
      OldFlatsize    = 21
      Pkgsize        = 22
      LicenseLogic   = 23
      Automatic      = 24
      Locked         = 25
      Rowid          = 26
      Time           = 27
      Annotations    = 28
      Uniqueid       = 29
      OldDigest      = 30
      DepFormula     = 31
      Vital          = 32
      Categories     = 33
      Licenses       = 34
      Groups         = 35
      Users          = 36
      ShlibsRequired = 37
      ShlibsProvided = 38
      Provides       = 39
      Requires       = 40
      Conflicts      = 41
    end

    enum PkgDepAttr : Int32
      Name    = 0
      Origin  = 1
      Version = 2
    end

    enum PkgdbField : Int32
      None        = 0
      Origin      = 1
      Name        = 2
      NameVer     = 3
      Comment     = 4
      Desc        = 5
      CommentDesc = 6
      Flavor      = 7
    end

    enum PkgInitFlags : UInt32
      UseIpv4 = 1
      UseIpv6 = 2
    end

    # -------------------------------------------------------------------
    # PKG_LOAD_* flags (passed as UInt32 to pkgdb_it_next)
    # -------------------------------------------------------------------
    PKG_LOAD_BASIC           =     0_u32
    PKG_LOAD_DEPS            =     1_u32
    PKG_LOAD_RDEPS           =     2_u32
    PKG_LOAD_FILES           =     4_u32
    PKG_LOAD_SCRIPTS         =     8_u32
    PKG_LOAD_OPTIONS         =    16_u32
    PKG_LOAD_DIRS            =    32_u32
    PKG_LOAD_CATEGORIES      =    64_u32
    PKG_LOAD_LICENSES        =   128_u32
    PKG_LOAD_USERS           =   256_u32
    PKG_LOAD_GROUPS          =   512_u32
    PKG_LOAD_SHLIBS_REQUIRED =  1024_u32
    PKG_LOAD_SHLIBS_PROVIDED =  2048_u32
    PKG_LOAD_ANNOTATIONS     =  4096_u32
    PKG_LOAD_CONFLICTS       =  8192_u32
    PKG_LOAD_PROVIDES        = 16384_u32
    PKG_LOAD_REQUIRES        = 32768_u32
    PKG_LOAD_LUA_SCRIPTS     = 65536_u32

    # -------------------------------------------------------------------
    # Initialization / shutdown
    # -------------------------------------------------------------------
    @[CallConvention("C")]
    fun pkg_ini(conffile : LibC::Char*, repodir : LibC::Char*, flags : PkgInitFlags) : Int32
    fun pkg_init(conffile : LibC::Char*, repodir : LibC::Char*) : Int32
    fun pkg_shutdown : Void
    fun pkg_initialized : Int32
    fun pkg_libversion : LibC::Char*

    # -------------------------------------------------------------------
    # Database open / close / lock
    # -------------------------------------------------------------------
    fun pkgdb_open(db : PkgDb*, type : PkgdbT) : Int32
    fun pkgdb_close(db : PkgDb) : Void
    fun pkgdb_obtain_lock(db : PkgDb, type : PkgdbLockT) : Int32
    fun pkgdb_release_lock(db : PkgDb, type : PkgdbLockT) : Int32
    fun pkgdb_set_case_sensitivity(sensitive : Bool) : Void
    fun pkgdb_case_sensitive : Bool

    # -------------------------------------------------------------------
    # Query functions → pkgdb_it*
    # -------------------------------------------------------------------
    fun pkgdb_query(db : PkgDb, pattern : LibC::Char*, type : MatchT) : PkgDbIt
    fun pkgdb_query_cond(db : PkgDb, cond : LibC::Char*, pattern : LibC::Char*, type : MatchT) : PkgDbIt
    fun pkgdb_repo_query(db : PkgDb, pattern : LibC::Char*, type : MatchT, reponame : LibC::Char*) : PkgDbIt
    fun pkgdb_repo_search(db : PkgDb, pattern : LibC::Char*, type : MatchT,
                          field : PkgdbField, sort : PkgdbField, reponame : LibC::Char*) : PkgDbIt
    fun pkgdb_all_search(db : PkgDb, pattern : LibC::Char*, type : MatchT,
                         field : PkgdbField, sort : PkgdbField, reponame : LibC::Char*) : PkgDbIt
    fun pkgdb_query_which(db : PkgDb, path : LibC::Char*, glob : Bool) : PkgDbIt
    fun pkgdb_query_shlib_require(db : PkgDb, shlib : LibC::Char*) : PkgDbIt
    fun pkgdb_query_shlib_provide(db : PkgDb, shlib : LibC::Char*) : PkgDbIt
    fun pkgdb_query_require(db : PkgDb, req : LibC::Char*) : PkgDbIt
    fun pkgdb_query_provide(db : PkgDb, req : LibC::Char*) : PkgDbIt

    # -------------------------------------------------------------------
    # Iterator
    # -------------------------------------------------------------------
    fun pkgdb_it_next(it : PkgDbIt, pkg : PkgHandle*, flags : UInt32) : Int32
    fun pkgdb_it_reset(it : PkgDbIt) : Void
    fun pkgdb_it_count(it : PkgDbIt) : Int32
    fun pkgdb_it_free(it : PkgDbIt) : Void

    # -------------------------------------------------------------------
    # Package lifecycle
    # -------------------------------------------------------------------
    fun pkg_new(pkg : PkgHandle*, type : PkgT) : Int32
    fun pkg_free(pkg : PkgHandle) : Void
    fun pkg_open(pkg : PkgHandle*, path : LibC::Char*, flags : Int32) : Int32
    fun pkg_type(pkg : PkgHandle) : PkgT
    fun pkg_is_valid(pkg : PkgHandle) : Int32
    fun pkg_is_installed(db : PkgDb, name : LibC::Char*) : Int32

    # -------------------------------------------------------------------
    # Package attribute access
    #
    # pkg_get_element returns a heap-allocated PkgEl*.
    # Caller must LibC.free() it after use.
    # -------------------------------------------------------------------
    fun pkg_get_element(pkg : PkgHandle, attr : PkgAttr) : PkgEl*

    # -------------------------------------------------------------------
    # kvlist / stringlist iteration (for PkgElT::KvList / PkgElT::StringList)
    # -------------------------------------------------------------------
    fun pkg_kvlist_iterator(list : PkgKvlist) : PkgKvlistIt
    fun pkg_kvlist_next(it : PkgKvlistIt) : LibC::Char** # returns char*[2]: [key, value]
    fun pkg_stringlist_iterator(list : PkgStringlist) : PkgStringlistIt
    fun pkg_stringlist_next(it : PkgStringlistIt) : LibC::Char*

    # -------------------------------------------------------------------
    # Dependency iteration (linked-list cursor: pass PkgDep* init to null)
    # -------------------------------------------------------------------
    fun pkg_deps(pkg : PkgHandle, dep : PkgDep*) : Int32
    fun pkg_rdeps(pkg : PkgHandle, dep : PkgDep*) : Int32
    fun pkg_dep_get(dep : PkgDep, attr : PkgDepAttr) : LibC::Char*
    fun pkg_dep_is_locked(dep : PkgDep) : Bool

    # -------------------------------------------------------------------
    # File / directory iteration and lookup
    # -------------------------------------------------------------------
    fun pkg_files(pkg : PkgHandle, file : PkgFile*) : Int32
    fun pkg_dirs(pkg : PkgHandle, dir : PkgDir*) : Int32
    fun pkg_has_file(pkg : PkgHandle, path : LibC::Char*) : Bool
    fun pkg_has_dir(pkg : PkgHandle, path : LibC::Char*) : Bool
    fun pkg_get_file(pkg : PkgHandle, path : LibC::Char*) : PkgFile
    fun pkg_get_dir(pkg : PkgHandle, path : LibC::Char*) : PkgDir

    # -------------------------------------------------------------------
    # Other relation iteration
    # -------------------------------------------------------------------
    fun pkg_options(pkg : PkgHandle, option : PkgOption*) : Int32
    fun pkg_conflicts(pkg : PkgHandle, conflict : PkgConflict*) : Int32
    fun pkg_config_files(pkg : PkgHandle, cf : PkgCfgFile*) : Int32

    # -------------------------------------------------------------------
    # Version comparison
    # -------------------------------------------------------------------
    fun pkg_version_cmp(v1 : LibC::Char*, v2 : LibC::Char*) : Int32

    # -------------------------------------------------------------------
    # Repository info
    # -------------------------------------------------------------------
    fun pkg_repos_total_count : Int32
    fun pkg_repos_activated_count : Int32
    fun pkg_repos(repo : PkgRepo*) : Int32
    fun pkg_repo_url(repo : PkgRepo) : LibC::Char*
    fun pkg_repo_name(repo : PkgRepo) : LibC::Char*
    fun pkg_repo_key(repo : PkgRepo) : LibC::Char*
    fun pkg_repo_enabled(repo : PkgRepo) : Bool
    fun pkg_repo_priority(repo : PkgRepo) : Int32
    fun pkg_repo_find(name : LibC::Char*) : PkgRepo

    # -------------------------------------------------------------------
    # Jobs API — install, remove, fetch, upgrade, autoremove
    # -------------------------------------------------------------------

    enum PkgJobsT : Int32
      Install    = 0
      Deinstall  = 1
      Fetch      = 2
      Autoremove = 3
      Upgrade    = 4
    end

    enum PkgSolvedT : Int32
      Install        = 0
      Delete         = 1
      Upgrade        = 2
      UpgradeRemove  = 3
      Fetch          = 4
      UpgradeInstall = 5
    end

    # pkg_set_attr values used with pkgdb_set2
    enum PkgSetAttr : UInt32
      Flatsize  = 1
      Automatic = 2
      Locked    = 3
      Deporigin = 4
      Origin    = 5
      Depname   = 6
      Name      = 7
      Vital     = 8
    end

    # pkg_flags bitmask constants
    PKG_FLAG_DRY_RUN                =      1_u32 # (1U << 0)
    PKG_FLAG_FORCE                  =      2_u32 # (1U << 1)
    PKG_FLAG_RECURSIVE              =      4_u32 # (1U << 2)
    PKG_FLAG_AUTOMATIC              =      8_u32 # (1U << 3)
    PKG_FLAG_WITH_DEPS              =     16_u32 # (1U << 4)
    PKG_FLAG_NOSCRIPT               =     32_u32 # (1U << 5)
    PKG_FLAG_PKG_VERSION_TEST       =     64_u32 # (1U << 6)
    PKG_FLAG_UPGRADES_FOR_INSTALLED =    128_u32 # (1U << 7)
    PKG_FLAG_SKIP_INSTALL           =    256_u32 # (1U << 8)
    PKG_FLAG_FORCE_MISSING          =    512_u32 # (1U << 9)
    PKG_FLAG_FETCH_MIRROR           =   1024_u32 # (1U << 10)
    PKG_FLAG_USE_IPV4               =   2048_u32 # (1U << 11)
    PKG_FLAG_USE_IPV6               =   4096_u32 # (1U << 12)
    PKG_FLAG_UPGRADE_VULNERABLE     =   8192_u32 # (1U << 13)
    PKG_FLAG_NOEXEC                 =  16384_u32 # (1U << 14)
    PKG_FLAG_KEEPFILES              =  32768_u32 # (1U << 15)
    PKG_FLAG_REGISTER_ONLY          =  65536_u32 # (1U << 16)
    PKG_FLAG_FETCH_SYMLINK          = 131072_u32 # (1U << 17)

    # pkg_add flags — note gap at bit 1 (PKG_ADD_SPLITTED_UPGRADE removed from public API)
    PKG_ADD_UPGRADE       =   1_u32 # (1U << 0)
    PKG_ADD_AUTOMATIC     =   4_u32 # (1U << 2)
    PKG_ADD_FORCE         =   8_u32 # (1U << 3)
    PKG_ADD_NOSCRIPT      =  16_u32 # (1U << 4)
    PKG_ADD_FORCE_MISSING =  32_u32 # (1U << 5)
    PKG_ADD_NOEXEC        = 128_u32 # (1U << 7)
    PKG_ADD_REGISTER_ONLY = 256_u32 # (1U << 8)

    # Jobs opaque type
    type PkgJobs = Void*

    fun pkg_jobs_new(jobs : PkgJobs*, type : PkgJobsT, db : PkgDb) : Int32
    fun pkg_jobs_free(jobs : PkgJobs) : Void
    fun pkg_jobs_add(jobs : PkgJobs, match : MatchT, argv : LibC::Char**, argc : Int32) : Int32
    fun pkg_jobs_solve(jobs : PkgJobs) : Int32
    fun pkg_jobs_apply(jobs : PkgJobs) : Int32
    fun pkg_jobs_set_flags(jobs : PkgJobs, flags : UInt32) : Void
    fun pkg_jobs_set_repository(jobs : PkgJobs, name : LibC::Char*) : Int32
    fun pkg_jobs_set_destdir(jobs : PkgJobs, name : LibC::Char*) : Int32
    fun pkg_jobs_destdir(jobs : PkgJobs) : LibC::Char*
    fun pkg_jobs_type(jobs : PkgJobs) : PkgJobsT
    fun pkg_jobs_count(jobs : PkgJobs) : Int32
    fun pkg_jobs_total(jobs : PkgJobs) : Int32
    fun pkg_jobs_has_lockedpkgs(jobs : PkgJobs) : Bool
    fun pkg_jobs_iter(jobs : PkgJobs, iter : Void**, n : PkgHandle*, o : PkgHandle*, type : Int32*) : Bool

    # -------------------------------------------------------------------
    # Direct local archive install (bypasses solver)
    # -------------------------------------------------------------------
    fun pkg_add(db : PkgDb, path : LibC::Char*, flags : UInt32, location : LibC::Char*) : Int32

    # -------------------------------------------------------------------
    # Repository catalog refresh
    # -------------------------------------------------------------------
    fun pkg_update(repo : PkgRepo, force : Bool) : Int32

    # -------------------------------------------------------------------
    # In-memory package attribute setters
    # -------------------------------------------------------------------
    fun pkg_set_s(pkg : PkgHandle, a : PkgAttr, val : LibC::Char*) : Int32
    fun pkg_set_i(pkg : PkgHandle, a : PkgAttr, val : Int64) : Int32
    fun pkg_set_b(pkg : PkgHandle, a : PkgAttr, val : Bool) : Int32

    # Batch DB attribute update — variadic; terminate with -1
    fun pkgdb_set2(db : PkgDb, pkg : PkgHandle, ...) : Int32

    # -------------------------------------------------------------------
    # Annotation CRUD
    # -------------------------------------------------------------------
    fun pkgdb_add_annotation(db : PkgDb, pkg : PkgHandle, tag : LibC::Char*, value : LibC::Char*) : Int32
    fun pkgdb_modify_annotation(db : PkgDb, pkg : PkgHandle, tag : LibC::Char*, value : LibC::Char*) : Int32
    fun pkgdb_delete_annotation(db : PkgDb, pkg : PkgHandle, tag : LibC::Char*) : Int32

    # -------------------------------------------------------------------
    # Lock upgrade / downgrade
    # -------------------------------------------------------------------
    fun pkgdb_upgrade_lock(db : PkgDb, old_type : PkgdbLockT, new_type : PkgdbLockT) : Int32
    fun pkgdb_downgrade_lock(db : PkgDb, old_type : PkgdbLockT, new_type : PkgdbLockT) : Int32

    # -------------------------------------------------------------------
    # Transactions
    # -------------------------------------------------------------------
    fun pkgdb_transaction_begin(db : PkgDb, savepoint : LibC::Char*) : Int32
    fun pkgdb_transaction_commit(db : PkgDb, savepoint : LibC::Char*) : Int32
    fun pkgdb_transaction_rollback(db : PkgDb, savepoint : LibC::Char*) : Int32

    # -------------------------------------------------------------------
    # Event callback
    # -------------------------------------------------------------------

    # pkg_event_t discriminant values (two ranges: 0-36 normal, 65536+ error)
    enum PkgEventT : Int32
      InstallBegin              =     0
      InstallFinished           =     1
      DeinstallBegin            =     2
      DeinstallFinished         =     3
      UpgradeBegin              =     4
      UpgradeFinished           =     5
      ExtractBegin              =     6
      ExtractFinished           =     7
      DeleteFilesBegin          =     8
      DeleteFilesFinished       =     9
      AddDepsBegin              =    10
      AddDepsFinished           =    11
      Fetching                  =    12
      FetchBegin                =    13
      FetchFinished             =    14
      UpdateAdd                 =    15
      UpdateRemove              =    16
      IntegritycheckBegin       =    17
      IntegritycheckFinished    =    18
      IntegritycheckConflict    =    19
      NewpkgVersion             =    20
      Notice                    =    21
      Debug                     =    22
      IncrementalUpdateBegin    =    23
      IncrementalUpdate         =    24
      QueryYesno                =    25
      QuerySelect               =    26
      SandboxCall               =    27
      SandboxGetString          =    28
      ProgressStart             =    29
      ProgressTick              =    30
      Backup                    =    31
      Restore                   =    32
      FileMetaOk                =    33
      DirMetaOk                 =    34
      Error                     =    35
      Errno                     =    36
      ArchiveCompUnsup          = 65536
      AlreadyInstalled          = 65537
      FailedCksum               = 65538
      CreateDbError             = 65539
      Locked                    = 65540
      Required                  = 65541
      MissingDep                = 65542
      NoRemoteDb                = 65543
      NoLocalDb                 = 65544
      FileMismatch              = 65545
      DeveloperMode             = 65546
      PluginErrno               = 65547
      PluginError               = 65548
      PluginInfo                = 65549
      NotFound                  = 65550
      NewAction                 = 65551
      Message                   = 65552
      DirMissing                = 65553
      FileMissing               = 65554
      CleanupCallbackRegister   = 65555
      CleanupCallbackUnregister = 65556
      Conflicts                 = 65557
      TriggersBegin             = 65558
      Trigger                   = 65559
      TriggersFinished          = 65560
      PkgErrno                  = 65561
      FileMetaMismatch          = 65562
      DirMetaMismatch           = 65563
    end

    # struct pkg_event: type discriminant at offset 0 (4 bytes), union payload at offset 8.
    # We model only the type field; payload is accessed via pointer arithmetic in Crystal.
    struct PkgEvent
      type : PkgEventT
    end

    # Event callback type: (userdata*, event*) -> Int32
    alias PkgEventCb = (Void*, PkgEvent*) -> Int32

    fun pkg_event_register(cb : PkgEventCb, data : Void*) : Void
  end
{% else %}
  lib LibPkg
    type PkgHandle = Void*
    type PkgDb = Void*
    type PkgDbIt = Void*
    type PkgDep = Void*
    type PkgFile = Void*
    type PkgDir = Void*
    type PkgRepo = Void*
    type PkgJobs = Void*
    type PkgKvlist = Void*
    type PkgStringlist = Void*

    enum PkgEventT : Int32
      InstallBegin = 0
    end

    struct PkgEvent
      type : PkgEventT
    end

    alias PkgEventCb = (Void*, PkgEvent*) -> Int32
  end
{% end %}
