use protobuf::Message;
use std::fmt::Debug;
use std::io::Read;
use steam_vent_proto::{
    steammessages_chat_steamclient, steammessages_credentials_steamclient,
    steammessages_deviceauth_steamclient, steammessages_econ_steamclient,
    steammessages_friendmessages_steamclient, steammessages_gameservers_steamclient,
    steammessages_player_steamclient, steammessages_publishedfile_steamclient,
    steammessages_store_steamclient, steammessages_twofactor_steamclient,
    steammessages_useraccount_steamclient,
};

pub trait ServiceMethodRequest: Debug + Message {
    const REQ_NAME: &'static str;
    type Response: ServiceMethodResponse;
}

pub trait ServiceMethodResponse: Debug + Sized {
    fn parse_from_reader(reader: &mut dyn Read) -> protobuf::Result<Self>;
}

impl ServiceMethodResponse for () {
    fn parse_from_reader(_reader: &mut dyn Read) -> protobuf::Result<Self> {
        Ok(())
    }
}

macro_rules! service_method {
    ($name:literal => $req:path, $res:path) => {
        impl ServiceMethodRequest for $req {
            const REQ_NAME: &'static str = concat!($name, "#1");
            type Response = $res;
        }

        impl ServiceMethodResponse for $res {
            fn parse_from_reader(reader: &mut dyn Read) -> protobuf::Result<Self> {
                <Self as Message>::parse_from_reader(reader)
            }
        }
    };
    ($name:literal => $req:path) => {
        impl ServiceMethodRequest for $req {
            const REQ_NAME: &'static str = concat!($name, "#1");
            type Response = ();
        }
    };
}

service_method!("GameServers.GetServerList" => steammessages_gameservers_steamclient::CGameServers_GetServerList_Request, steammessages_gameservers_steamclient::CGameServers_GetServerList_Response);
// service_method!("GameServers.GetServerSteamIDsByIP" => steammessages_gameservers_steamclient::CGameServers_GetServerSteamIDsByIP_Request, steammessages_gameservers_steamclient::CGameServers_IPsWithSteamIDs_Response);
service_method!("GameServers.GetServerIPsBySteamID" => steammessages_gameservers_steamclient::CGameServers_GetServerIPsBySteamID_Request, steammessages_gameservers_steamclient::CGameServers_IPsWithSteamIDs_Response);
service_method!("TwoFactor.AddAuthenticator" => steammessages_twofactor_steamclient::CTwoFactor_AddAuthenticator_Request, steammessages_twofactor_steamclient::CTwoFactor_AddAuthenticator_Response);
service_method!("TwoFactor.FinalizeAddAuthenticator" => steammessages_twofactor_steamclient::CTwoFactor_FinalizeAddAuthenticator_Request, steammessages_twofactor_steamclient::CTwoFactor_FinalizeAddAuthenticator_Response);
service_method!("TwoFactor.SendEmail" => steammessages_twofactor_steamclient::CTwoFactor_SendEmail_Request, steammessages_twofactor_steamclient::CTwoFactor_SendEmail_Response);
service_method!("TwoFactor.RemoveAuthenticator" => steammessages_twofactor_steamclient::CTwoFactor_RemoveAuthenticator_Request, steammessages_twofactor_steamclient::CTwoFactor_RemoveAuthenticator_Response);
service_method!("Credentials.GetSteamGuardDetails" => steammessages_credentials_steamclient::CCredentials_GetSteamGuardDetails_Request, steammessages_credentials_steamclient::CCredentials_GetSteamGuardDetails_Response);
service_method!("Credentials.GetAccountAuthSecret" => steammessages_credentials_steamclient::CCredentials_GetAccountAuthSecret_Request, steammessages_credentials_steamclient::CCredentials_GetAccountAuthSecret_Response);
service_method!("Credentials.GetCredentialChangeTimeDetails" => steammessages_credentials_steamclient::CCredentials_LastCredentialChangeTime_Request, steammessages_credentials_steamclient::CCredentials_LastCredentialChangeTime_Response);
service_method!("PublishedFile.GetDetails" => steammessages_publishedfile_steamclient::CPublishedFile_GetDetails_Request, steammessages_publishedfile_steamclient::CPublishedFile_GetDetails_Response);
service_method!("Player.GetGameBadgeLevels" => steammessages_player_steamclient::CPlayer_GetGameBadgeLevels_Request, steammessages_player_steamclient::CPlayer_GetGameBadgeLevels_Response);
service_method!("Player.GetNicknameList" => steammessages_player_steamclient::CPlayer_GetNicknameList_Request, steammessages_player_steamclient::CPlayer_GetNicknameList_Response);
service_method!("Player.GetEmoticonList" => steammessages_player_steamclient::CPlayer_GetEmoticonList_Request, steammessages_player_steamclient::CPlayer_GetEmoticonList_Response);
service_method!("Player.GetPrivacySettings" => steammessages_player_steamclient::CPlayer_GetPrivacySettings_Request, steammessages_player_steamclient::CPlayer_GetPrivacySettings_Response);
service_method!("Player.GetOwnedGames" => steammessages_player_steamclient::CPlayer_GetOwnedGames_Request, steammessages_player_steamclient::CPlayer_GetOwnedGames_Response);
service_method!("Player.GetProfileItemsOwned" => steammessages_player_steamclient::CPlayer_GetProfileItemsOwned_Request, steammessages_player_steamclient::CPlayer_GetProfileItemsOwned_Response);
service_method!("Player.GetProfileItemsEquipped" => steammessages_player_steamclient::CPlayer_GetProfileItemsEquipped_Request, steammessages_player_steamclient::CPlayer_GetProfileItemsEquipped_Response);
service_method!("Player.GetProfileBackground" => steammessages_player_steamclient::CPlayer_GetProfileBackground_Request, steammessages_player_steamclient::CPlayer_GetProfileBackground_Response);
service_method!("Player.SetProfileBackground" => steammessages_player_steamclient::CPlayer_SetProfileBackground_Request, steammessages_player_steamclient::CPlayer_SetProfileBackground_Response);
service_method!("Econ.GetAssetClassInfo" => steammessages_econ_steamclient::CEcon_GetAssetClassInfo_Request, steammessages_econ_steamclient::CEcon_GetAssetClassInfo_Response);
service_method!("Store.GetLocalizedNameForTags" => steammessages_store_steamclient::CStore_GetLocalizedNameForTags_Request, steammessages_store_steamclient::CStore_GetLocalizedNameForTags_Response);
service_method!("Econ.GetTradeOfferAccessToken" => steammessages_econ_steamclient::CEcon_GetTradeOfferAccessToken_Request, steammessages_econ_steamclient::CEcon_GetTradeOfferAccessToken_Response);
service_method!("ChatRoom.CreateChatRoomGroup" => steammessages_chat_steamclient::CChatRoom_CreateChatRoomGroup_Request, steammessages_chat_steamclient::CChatRoom_CreateChatRoomGroup_Response);
service_method!("ChatRoom.SaveChatRoomGroup" => steammessages_chat_steamclient::CChatRoom_SaveChatRoomGroup_Request, steammessages_chat_steamclient::CChatRoom_SaveChatRoomGroup_Response);
service_method!("ChatRoom.RenameChatRoomGroup" => steammessages_chat_steamclient::CChatRoom_RenameChatRoomGroup_Request, steammessages_chat_steamclient::CChatRoom_RenameChatRoomGroup_Response);
service_method!("ChatRoom.SetChatRoomGroupTagline" => steammessages_chat_steamclient::CChatRoom_SetChatRoomGroupTagline_Request, steammessages_chat_steamclient::CChatRoom_SetChatRoomGroupTagline_Response);
service_method!("ChatRoom.SetChatRoomGroupAvatar" => steammessages_chat_steamclient::CChatRoom_SetChatRoomGroupAvatar_Request, steammessages_chat_steamclient::CChatRoom_SetChatRoomGroupAvatar_Response);
service_method!("ChatRoom.MuteUserInGroup" => steammessages_chat_steamclient::CChatRoom_MuteUser_Request, steammessages_chat_steamclient::CChatRoom_MuteUser_Response);
service_method!("ChatRoom.KickUserFromGroup" => steammessages_chat_steamclient::CChatRoom_KickUser_Request, steammessages_chat_steamclient::CChatRoom_KickUser_Response);
service_method!("ChatRoom.SetUserBanState" => steammessages_chat_steamclient::CChatRoom_SetUserBanState_Request, steammessages_chat_steamclient::CChatRoom_SetUserBanState_Response);
service_method!("ChatRoom.RevokeInviteToGroup" => steammessages_chat_steamclient::CChatRoom_RevokeInvite_Request, steammessages_chat_steamclient::CChatRoom_RevokeInvite_Response);
service_method!("ChatRoom.CreateRole" => steammessages_chat_steamclient::CChatRoom_CreateRole_Request, steammessages_chat_steamclient::CChatRoom_CreateRole_Response);
service_method!("ChatRoom.GetRoles" => steammessages_chat_steamclient::CChatRoom_GetRoles_Request, steammessages_chat_steamclient::CChatRoom_GetRoles_Response);
service_method!("ChatRoom.RenameRole" => steammessages_chat_steamclient::CChatRoom_RenameRole_Request, steammessages_chat_steamclient::CChatRoom_RenameRole_Response);
service_method!("ChatRoom.ReorderRole" => steammessages_chat_steamclient::CChatRoom_ReorderRole_Request, steammessages_chat_steamclient::CChatRoom_ReorderRole_Response);
service_method!("ChatRoom.DeleteRole" => steammessages_chat_steamclient::CChatRoom_DeleteRole_Request, steammessages_chat_steamclient::CChatRoom_DeleteRole_Response);
service_method!("ChatRoom.GetRoleActions" => steammessages_chat_steamclient::CChatRoom_GetRoleActions_Request, steammessages_chat_steamclient::CChatRoom_GetRoleActions_Response);
service_method!("ChatRoom.ReplaceRoleActions" => steammessages_chat_steamclient::CChatRoom_ReplaceRoleActions_Request, steammessages_chat_steamclient::CChatRoom_ReplaceRoleActions_Response);
service_method!("ChatRoom.AddRoleToUser" => steammessages_chat_steamclient::CChatRoom_AddRoleToUser_Request, steammessages_chat_steamclient::CChatRoom_AddRoleToUser_Response);
service_method!("ChatRoom.GetRolesForUser" => steammessages_chat_steamclient::CChatRoom_GetRolesForUser_Request, steammessages_chat_steamclient::CChatRoom_GetRolesForUser_Response);
service_method!("ChatRoom.DeleteRoleFromUser" => steammessages_chat_steamclient::CChatRoom_DeleteRoleFromUser_Request, steammessages_chat_steamclient::CChatRoom_DeleteRoleFromUser_Response);
service_method!("ChatRoom.JoinChatRoomGroup" => steammessages_chat_steamclient::CChatRoom_JoinChatRoomGroup_Request, steammessages_chat_steamclient::CChatRoom_JoinChatRoomGroup_Response);
service_method!("ChatRoom.InviteFriendToChatRoomGroup" => steammessages_chat_steamclient::CChatRoom_InviteFriendToChatRoomGroup_Request, steammessages_chat_steamclient::CChatRoom_InviteFriendToChatRoomGroup_Response);
service_method!("ChatRoom.LeaveChatRoomGroup" => steammessages_chat_steamclient::CChatRoom_LeaveChatRoomGroup_Request, steammessages_chat_steamclient::CChatRoom_LeaveChatRoomGroup_Response);
service_method!("ChatRoom.CreateChatRoom" => steammessages_chat_steamclient::CChatRoom_CreateChatRoom_Request, steammessages_chat_steamclient::CChatRoom_CreateChatRoom_Response);
service_method!("ChatRoom.DeleteChatRoom" => steammessages_chat_steamclient::CChatRoom_DeleteChatRoom_Request, steammessages_chat_steamclient::CChatRoom_DeleteChatRoom_Response);
service_method!("ChatRoom.RenameChatRoom" => steammessages_chat_steamclient::CChatRoom_RenameChatRoom_Request, steammessages_chat_steamclient::CChatRoom_RenameChatRoom_Response);
service_method!("ChatRoom.SendChatMessage" => steammessages_chat_steamclient::CChatRoom_SendChatMessage_Request, steammessages_chat_steamclient::CChatRoom_SendChatMessage_Response);
service_method!("ChatRoom.JoinVoiceChat" => steammessages_chat_steamclient::CChatRoom_JoinVoiceChat_Request, steammessages_chat_steamclient::CChatRoom_JoinVoiceChat_Response);
service_method!("ChatRoom.LeaveVoiceChat" => steammessages_chat_steamclient::CChatRoom_LeaveVoiceChat_Request, steammessages_chat_steamclient::CChatRoom_LeaveVoiceChat_Response);
service_method!("ChatRoom.GetMessageHistory" => steammessages_chat_steamclient::CChatRoom_GetMessageHistory_Request, steammessages_chat_steamclient::CChatRoom_GetMessageHistory_Response);
service_method!("ChatRoom.GetMyChatRoomGroups" => steammessages_chat_steamclient::CChatRoom_GetMyChatRoomGroups_Request, steammessages_chat_steamclient::CChatRoom_GetMyChatRoomGroups_Response);
service_method!("ChatRoom.GetChatRoomGroupState" => steammessages_chat_steamclient::CChatRoom_GetChatRoomGroupState_Request, steammessages_chat_steamclient::CChatRoom_GetChatRoomGroupState_Response);
service_method!("ChatRoom.GetChatRoomGroupSummary" => steammessages_chat_steamclient::CChatRoom_GetChatRoomGroupSummary_Request, steammessages_chat_steamclient::CChatRoom_GetChatRoomGroupSummary_Request);
service_method!("ChatRoom.CreateInviteLink" => steammessages_chat_steamclient::CChatRoom_CreateInviteLink_Request, steammessages_chat_steamclient::CChatRoom_CreateInviteLink_Response);
service_method!("ChatRoom.GetInviteLinkInfo" => steammessages_chat_steamclient::CChatRoom_GetInviteLinkInfo_Request, steammessages_chat_steamclient::CChatRoom_GetInviteLinkInfo_Response);
service_method!("ChatRoom.GetInviteInfo" => steammessages_chat_steamclient::CChatRoom_GetInviteInfo_Request, steammessages_chat_steamclient::CChatRoom_GetInviteInfo_Response);
service_method!("ChatRoom.GetInviteLinksForGroup" => steammessages_chat_steamclient::CChatRoom_GetInviteLinksForGroup_Request, steammessages_chat_steamclient::CChatRoom_GetInviteLinksForGroup_Response);
service_method!("ChatRoom.GetBanList" => steammessages_chat_steamclient::CChatRoom_GetBanList_Request, steammessages_chat_steamclient::CChatRoom_GetBanList_Response);
service_method!("ChatRoom.GetInviteList" => steammessages_chat_steamclient::CChatRoom_GetInviteList_Request, steammessages_chat_steamclient::CChatRoom_GetInviteList_Response);
service_method!("ChatRoom.DeleteInviteLink" => steammessages_chat_steamclient::CChatRoom_DeleteInviteLink_Request, steammessages_chat_steamclient::CChatRoom_DeleteInviteLink_Response);
service_method!("ChatRoom.SetSessionActiveChatRoomGroups" => steammessages_chat_steamclient::CChatRoom_SetSessionActiveChatRoomGroups_Request, steammessages_chat_steamclient::CChatRoom_SetSessionActiveChatRoomGroups_Response);
// service_method!("ChatRoom.SetUserChatPreferences" => steammessages_chat_steamclient::SetUserChatPre, steammessages_chat_steamclient::CChatRoom_SetUserChatPreferences_Response);
service_method!("ChatRoom.SetUserChatGroupPreferences" => steammessages_chat_steamclient::CChatRoom_SetUserChatGroupPreferences_Request, steammessages_chat_steamclient::CChatRoom_SetUserChatGroupPreferences_Response);
service_method!("ChatRoom.DeleteChatMessages" => steammessages_chat_steamclient::CChatRoom_DeleteChatMessages_Request, steammessages_chat_steamclient::CChatRoom_DeleteChatMessages_Response);
service_method!("ClanChatRooms.GetClanChatRoomInfo" => steammessages_chat_steamclient::CClanChatRooms_GetClanChatRoomInfo_Request, steammessages_chat_steamclient::CClanChatRooms_GetClanChatRoomInfo_Response);
service_method!("FriendMessages.GetRecentMessages" => steammessages_friendmessages_steamclient::CFriendMessages_GetRecentMessages_Request, steammessages_friendmessages_steamclient::CFriendMessages_GetRecentMessages_Response);
service_method!("FriendMessages.GetActiveMessageSessions" => steammessages_friendmessages_steamclient::CFriendsMessages_GetActiveMessageSessions_Request, steammessages_friendmessages_steamclient::CFriendsMessages_GetActiveMessageSessions_Response);
service_method!("FriendMessages.SendMessage" => steammessages_friendmessages_steamclient::CFriendMessages_SendMessage_Request, steammessages_friendmessages_steamclient::CFriendMessages_SendMessage_Response);
service_method!("FriendMessages.IsInFriendsUIBeta" => steammessages_friendmessages_steamclient::CFriendMessages_IsInFriendsUIBeta_Request, steammessages_friendmessages_steamclient::CFriendMessages_IsInFriendsUIBeta_Response);
// service_method!("Community.GetAppRichPresenceLocalization" => Schema.CCommunity_GetAppRichPresenceLocalization_Request);
service_method!("UserAccount.CreateFriendInviteToken" => steammessages_useraccount_steamclient::CUserAccount_CreateFriendInviteToken_Request, steammessages_useraccount_steamclient::CUserAccount_CreateFriendInviteToken_Response);
service_method!("UserAccount.GetFriendInviteTokens" => steammessages_useraccount_steamclient::CUserAccount_GetFriendInviteTokens_Request, steammessages_useraccount_steamclient::CUserAccount_GetFriendInviteTokens_Response);
service_method!("UserAccount.ViewFriendInviteToken" => steammessages_useraccount_steamclient::CUserAccount_ViewFriendInviteToken_Request, steammessages_useraccount_steamclient::CUserAccount_ViewFriendInviteToken_Response);
service_method!("UserAccount.RedeemFriendInviteToken" => steammessages_useraccount_steamclient::CUserAccount_RedeemFriendInviteToken_Request, steammessages_useraccount_steamclient::CUserAccount_RedeemFriendInviteToken_Response);
service_method!("UserAccount.RevokeFriendInviteToken" => steammessages_useraccount_steamclient::CUserAccount_RevokeFriendInviteToken_Request, steammessages_useraccount_steamclient::CUserAccount_RevokeFriendInviteToken_Response);
service_method!("DeviceAuth.GetOwnAuthorizedDevices" => steammessages_deviceauth_steamclient::CDeviceAuth_GetOwnAuthorizedDevices_Request, steammessages_deviceauth_steamclient::CDeviceAuth_GetOwnAuthorizedDevices_Response);
service_method!("DeviceAuth.AddAuthorizedBorrowers" => steammessages_deviceauth_steamclient::CDeviceAuth_AddAuthorizedBorrowers_Request, steammessages_deviceauth_steamclient::CDeviceAuth_AddAuthorizedBorrowers_Response);
service_method!("DeviceAuth.RemoveAuthorizedBorrowers" => steammessages_deviceauth_steamclient::CDeviceAuth_RemoveAuthorizedBorrowers_Request, steammessages_deviceauth_steamclient::CDeviceAuth_RemoveAuthorizedBorrowers_Response);
service_method!("DeviceAuth.GetAuthorizedBorrowers" => steammessages_deviceauth_steamclient::CDeviceAuth_GetAuthorizedBorrowers_Request, steammessages_deviceauth_steamclient::CDeviceAuth_GetAuthorizedBorrowers_Response);
service_method!("Authentication.GetPasswordRSAPublicKey" => steam_vent_proto::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request, steam_vent_proto::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Response);
service_method!("IAuthenticationService.BeginAuthSessionViaCredentials" => steam_vent_proto::steammessages_auth_steamclient::CAuthentication_BeginAuthSessionViaCredentials_Request, steam_vent_proto::steammessages_auth_steamclient::CAuthentication_BeginAuthSessionViaCredentials_Response);

service_method!("ChatRoom.AckChatMessage" => steammessages_chat_steamclient::CChatRoom_AckChatMessage_Notification);
service_method!("FriendMessagesClient.IncomingMessage" => steammessages_friendmessages_steamclient::CFriendMessages_IncomingMessage_Notification);
// service_method!("FriendMessagesClient.NotifyAckMessageEcho" => steammessages_friendmessages_steamclient::CFriendMessages_AckMessage_Notification);
service_method!("FriendMessages.AckMessage" => steammessages_friendmessages_steamclient::CFriendMessages_AckMessage_Notification);
service_method!("ChatRoomClient.NotifyIncomingChatMessage" => steammessages_chat_steamclient::CChatRoom_IncomingChatMessage_Notification);
service_method!("ChatRoomClient.NotifyChatMessageModified" => steammessages_chat_steamclient::CChatRoom_ChatMessageModified_Notification);
service_method!("ChatRoomClient.NotifyMemberStateChange" => steammessages_chat_steamclient::CChatRoom_MemberStateChange_Notification);
service_method!("ChatRoomClient.NotifyChatRoomHeaderStateChange" => steammessages_chat_steamclient::CChatRoom_ChatRoomHeaderState_Notification);
service_method!("ChatRoomClient.NotifyChatRoomGroupRoomsChange" => steammessages_chat_steamclient::CChatRoom_ChatRoomGroupRoomsChange_Notification);
service_method!("ChatRoomClient.NotifyShouldRejoinChatRoomVoiceChat" => steammessages_chat_steamclient::CChatRoom_NotifyShouldRejoinChatRoomVoiceChat_Notification);
// service_method!("ChatRoomClient.NotifyChatUserPreferencesChanged" => steammessages_chat_steamclient::ChatRoomClient_NotifyChatUserPreferencesChanged_Notification);
service_method!("ChatRoomClient.NotifyChatGroupUserStateChanged" => steammessages_chat_steamclient::ChatRoomClient_NotifyChatGroupUserStateChanged_Notification);
// service_method!("ChatRoomClient.NotifyAckChatMessageEcho" => steammessages_chat_steamclient::CChatRoom_AckChatMessage_Notification);
service_method!("PlayerClient.NotifyFriendNicknameChanged" => steammessages_player_steamclient::CPlayer_FriendNicknameChanged_Notification);
