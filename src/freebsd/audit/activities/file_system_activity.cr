module FreeBSD::Audit::FileSystemActivity
  # OCSF 1001 activity_id values for File System Activity events.
  enum Activity : UInt8
    Unknown       =  0
    Create        =  1
    Read          =  2
    Update        =  3
    Delete        =  4
    Rename        =  5
    SetAttributes =  6
    SetSecurity   =  7
    GetAttributes =  8
    GetSecurity   =  9
    Encrypt       = 10
    Decrypt       = 11
    Mount         = 12
    Unmount       = 13
    Open          = 14
    Other         = 99

    def aue : AUE
      AUE::FileSystemActivity
    end
  end
end
