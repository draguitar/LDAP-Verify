package mizuho.com.util;

import java.util.Hashtable;
import java.util.ResourceBundle;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.commons.lang3.StringUtils;
import org.jasypt.util.text.BasicTextEncryptor;

import mizuho.com.VO.ADResultModel;
import mizuho.com.VO.LoginResultModel;

public class ADVerify {
	public LoginResultModel verify(String account, String password, String domainName) {
		LoginResultModel rtn = new LoginResultModel() ;
		ResourceBundle res = ResourceBundle.getBundle("config");
		String ldapURL = res.getString("Active.directory.ldapURL");
		try{
		   LDAP_AUTH_AD(ldapURL, account, password, domainName);
		   rtn.setRtnMsg("AD驗證成功");
		   rtn.setStatus(true);
		   
		   ADResultModel md = LDAP_SEARCH(account);
		   rtn.setDisplayName(md.getDisplayName());
		   return rtn ;
		}catch (Exception e){
			rtn.setRtnMsg("AD認證失敗!!"+e.getMessage());
			rtn.setStatus(false);
			return rtn ;
		}
	}
	public static void LDAP_AUTH_AD(String ldap_url, String account, String password, String domainName) throws Exception {
    	if (account.isEmpty() || password.isEmpty()) throw new Exception("認證失敗!");
    		
    	
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldap_url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, account + "@" + domainName);
        env.put(Context.SECURITY_CREDENTIALS, password);

        LdapContext ctx = null;
        try {
            ctx = new InitialLdapContext(env, null);
        } catch (AuthenticationException e) {
        	String errMsg = "" ;
        	/**
        	* DATA Code 說明 : 
        	* 525 : 用戶沒有找到
        	* 52e : 帳密錯誤
        	* 530 : 此時間不允許登入(not permitted to logon at this time)
        	* 532 : 密碼期滿
        	* 533 : 帳號停用
        	* 701 : 帳戶期滿
        	* 773 : 用戶必須重設密碼
        	* data 後面為錯誤代碼
        	*/
        	
        	if(e.getMessage().contains("52e")) {
        		errMsg = "帳密錯誤" ;
			}else if(e.getMessage().contains("533")){ 
				errMsg = "密碼期滿" ;
			}else if(e.getMessage().contains("532")){
				errMsg = "密碼期滿" ;
			}else if(e.getMessage().contains("701")){ 
				errMsg = "帳戶期滿" ;
			}else if(e.getMessage().contains("773")){
				errMsg = "用戶必須重設密碼" ;
			}
        	throw new Exception(errMsg + "!!");
        } catch (CommunicationException e) {
        	throw new Exception("伺服器連線失敗!");
        } catch (Exception e) {
        	throw new Exception("發生未知的錯誤!");
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException e) {
                }
            }
        }      
    }
	public static ADResultModel LDAP_SEARCH (String userAccount) throws NamingException{
		ResourceBundle res = ResourceBundle.getBundle("config");
		String ldapURL = res.getString("Active.directory.ldapURL");
		String domainName = res.getString("Domain.name");
		String account = res.getString("Active.directory.account");
		
		BasicTextEncryptor textEncryptor2 = new BasicTextEncryptor();
		textEncryptor2.setPassword("MHCBTWTP");
		String password = textEncryptor2.decrypt(res.getString("Active.directory.wordpass"));
		
		Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);
        if(!StringUtils.isEmpty(account)){
	        env.put(Context.SECURITY_AUTHENTICATION, "simple");
	        env.put(Context.SECURITY_PRINCIPAL, account+"@"+domainName);
	        env.put(Context.SECURITY_CREDENTIALS, password);
        }
        
        LdapContext ldapContext = new InitialLdapContext(env, null);
		
		SearchControls searchCtls = new SearchControls();
		String returnedAtts[] = { "sn", "givenName", "samAccountName" };
		
		searchCtls.setReturningAttributes(returnedAtts);
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		String searchFilter = "(&(userPrincipalName="+userAccount+"@"+domainName+"))";
		String searchBase = res.getString("Active.directory.searchBase");
		
		
		// initialize counter to total the results
		int totalResults = 0;

		// Search for objects using the filter
		NamingEnumeration<SearchResult> answer = ldapContext.search(searchBase,
				searchFilter, searchCtls);

		// Loop through the search results
		String displayName = "" ;
		while (answer.hasMoreElements()) {
			SearchResult sr = (SearchResult) answer.next();

			totalResults++;

//			System.out.println(">>>" + sr.getName());
			Attributes attrs = sr.getAttributes();
			displayName = sr.getName().replace("CN=", "");
			displayName = displayName.split(",")[0] ;
//			System.out.println(">>>>>>" + attrs.get("samAccountName"));
		}
		ADResultModel model = new ADResultModel();
		
		model.setTotalResults(totalResults);
		model.setDisplayName(displayName);
		
//		System.out.println("Total results: " + totalResults);
		ldapContext.close();
		
		return model ;
	
	}
	public static class User {
        private String distinguishedName;
        private String userPrincipal;
        private String commonName;
        public User(Attributes attr) throws javax.naming.NamingException {
            userPrincipal = (String) attr.get("userPrincipalName").get();
            commonName = (String) attr.get("cn").get();
            distinguishedName = (String) attr.get("distinguishedName").get();
 
        }
 
        public String getUserPrincipal(){
            return userPrincipal;
        }
 
        public String getCommonName(){
            return commonName;
        }
 
        public String getDistinguishedName(){
            return distinguishedName;
        }
 
        public String toString(){
            return getDistinguishedName();
        }
	}
}
