public without sharing class DateTimeAction {
    public class Input {
        @InvocableVariable(required=true)
        public String messagingSessionIdString;
    }
    public class Output {
        @InvocableVariable
        public String dateTimeString;
        @InvocableVariable
        public String debugJson;
    }

    @InvocableMethod(label='Answer the current date and time as a string')
    public static List<Output> run(List<Input> inputs) {
        List<Output> results = new List<Output>();

        for (Input i : inputs) {
            Output out = new Output();
            try {
                out.dateTimeString = '料理の完成は' + Datetime.now().format('yyyy-MM-dd HH:mm:ss') + 'です。';
                out.debugJson = buildDebugJson(i.messagingSessionIdString);
              } catch (Exception e) {
                out.debugJson = 'エラーが発生しました: ' + e.getMessage();
            }
            System.debug('debugJson: ' + out.debugJson);
            results.add(out);
        }
        return results;
    }

    private static String buildDebugJson(String messagingSessionIdString) {
        Map<String, Object> root = new Map<String, Object>();

        // UserInfo
        Map<String, Object> userInfoMap = new Map<String, Object>();
        userInfoMap.put('userName', UserInfo.getUserName());
        userInfoMap.put('userId', UserInfo.getUserId());
        root.put('userInfo', userInfoMap);
        root.put('messagingSessionIdString', messagingSessionIdString);

        if (String.isBlank(messagingSessionIdString)) {
            root.put('messagingSession', null);
            return JSON.serialize(root);
        }

        Id sessionId;
        try {
            sessionId = Id.valueOf(messagingSessionIdString.trim());
        } catch (Exception e) {
            root.put('messagingSession', null);
            root.put('error', 'Invalid MessagingSession Id: ' + e.getMessage());
            return JSON.serialize(root);
        }

        List<MessagingSession> sessions = [
            SELECT Id, ChannelKey, ChannelName, EndUserAccountId, EndUserContactId,
                   MessagingEndUserId, TargetUserId, ConversationId
            FROM MessagingSession
            WHERE Id = :sessionId
            LIMIT 1
        ];

        if (sessions.isEmpty()) {
            root.put('messagingSession', null);
            return JSON.serialize(root);
        }

        MessagingSession ms = sessions[0];
        Map<String, Object> sessionMap = new Map<String, Object>{
            'channelKey' => ms.ChannelKey,
            'channelName' => ms.ChannelName,
            'endUserAccountId' => ms.EndUserAccountId,
            'endUserContactId' => ms.EndUserContactId,
            'messagingEndUserId' => ms.MessagingEndUserId,
            'targetUserId' => ms.TargetUserId,
            'conversationId' => ms.ConversationId
        };

        // Account (EndUserAccountId)
        if (ms.EndUserAccountId != null) {
            List<Account> accounts = [SELECT Id, Name FROM Account WHERE Id = :ms.EndUserAccountId LIMIT 1];
            if (!accounts.isEmpty()) {
                sessionMap.put('endUserAccount', new Map<String, Object>{ 'name' => accounts[0].Name });
            }
        }

        // Contact (EndUserContactId)
        if (ms.EndUserContactId != null) {
            List<Contact> contacts = [SELECT Id, Name FROM Contact WHERE Id = :ms.EndUserContactId LIMIT 1];
            if (!contacts.isEmpty()) {
                sessionMap.put('endUserContact', new Map<String, Object>{ 'name' => contacts[0].Name });
            }
        }

        // MessagingEndUser
        if (ms.MessagingEndUserId != null) {
            List<MessagingEndUser> meus = [
                SELECT Id, Name, AccountId, ContactId, MessagingPlatformKey
                FROM MessagingEndUser
                WHERE Id = :ms.MessagingEndUserId
                LIMIT 1
            ];
            if (!meus.isEmpty()) {
                MessagingEndUser meu = meus[0];
                Map<String, Object> meuMap = new Map<String, Object>{ 'name' => meu.Name };
                meuMap.put('accountId', meu.AccountId);
                meuMap.put('contactId', meu.ContactId);
                meuMap.put('messagingPlatformKey', meu.MessagingPlatformKey);
                if (meu.AccountId != null) {
                    List<Account> accs = [SELECT Id, Name FROM Account WHERE Id = :meu.AccountId LIMIT 1];
                    if (!accs.isEmpty()) {
                        meuMap.put('account', new Map<String, Object>{ 'name' => accs[0].Name });
                    }
                }
                if (meu.ContactId != null) {
                    List<Contact> conts = [SELECT Id, Name FROM Contact WHERE Id = :meu.ContactId LIMIT 1];
                    if (!conts.isEmpty()) {
                        meuMap.put('contact', new Map<String, Object>{ 'name' => conts[0].Name });
                    }
                }
                sessionMap.put('messagingEndUser', meuMap);
            }
        }

        // TargetUser (User)
        if (ms.TargetUserId != null) {
            List<User> users = [SELECT Id, Name FROM User WHERE Id = :ms.TargetUserId LIMIT 1];
            if (!users.isEmpty()) {
                sessionMap.put('targetUser', new Map<String, Object>{ 'username' => users[0].Username });
            }
        }

        // ConversationEntry by ConversationId
        if (ms.ConversationId != null) {
            // query ConversationIdentifier from Conversation object by ConversationId
            // in the same manner to Account and Contact queries above
            List<Conversation> conversations = [
                SELECT Id, ConversationIdentifier
                FROM Conversation
                WHERE Id = :ms.ConversationId
                LIMIT 1
            ];
            if (!conversations.isEmpty()) {
                sessionMap.put('conversationIdentifier', conversations[0].ConversationIdentifier);
            }
            List<Map<String, Object>> entriesList = new List<Map<String, Object>>();
            for (ConversationEntry ce : [
                SELECT Id, ConversationId, ActorId, ActorName, ActorType, EntryType, Message,
                       MessageSendTime, CreatedDate
                FROM ConversationEntry
                WHERE ConversationId = :ms.ConversationId
                ORDER BY CreatedDate
            ]) {
                entriesList.add(new Map<String, Object>{
                    'conversationId' => ce.ConversationId,
                    'actorId' => ce.ActorId,
                    'actorName' => ce.ActorName,
                    'actorType' => ce.ActorType,
                    'entryType' => ce.EntryType,
                    'message' => ce.Message,
                    'messageSendTime' => ce.MessageSendTime != null ? ce.MessageSendTime.format('yyyy-MM-dd HH:mm:ss') : null,
                    'createdDate' => ce.CreatedDate != null ? ce.CreatedDate.format('yyyy-MM-dd HH:mm:ss') : null
                });
            }
            sessionMap.put('conversationEntries', entriesList);
        } else {
            sessionMap.put('conversationEntries', new List<Map<String, Object>>());
        }

        root.put('messagingSession', sessionMap);
        return JSON.serialize(root);
    }
}
