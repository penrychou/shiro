package com.bawu.shiro;



import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple Quickstart application showing how to use Shiro's API.
 *
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main(String[] args) {
    	
    	//hello
    	
        // The easiest way to create a Shiro SecurityManager with configured
        // realms, users, roles and permissions is to use the simple INI config.
        // We'll do that by using a factory that can ingest a .ini file and
        // return a SecurityManager instance:

        // Use the shiro.ini file at the root of the classpath
        // (file: and url: prefixes load from files and urls respectively):
    	//创建SecurityManager的工厂类
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //创建SecurityManager
        SecurityManager securityManager = factory.getInstance();

        // for this simple example quickstart, make the SecurityManager
        // accessible as a JVM singleton.  Most applications wouldn't do this
        // and instead rely on their container configuration or web.xml for
        // webapps.  That is outside the scope of this simple quickstart, so
        // we'll just do the bare minimum so you can continue to get a feel
        // for things.
        SecurityUtils.setSecurityManager(securityManager);

        // Now that a simple Shiro environment is set up, let's see what you can do:

        // get the currently executing user:
        //获取Subject(用户)对象  SecurityUtils.getSubject()
        Subject currentUser = SecurityUtils.getSubject();

        // Do some stuff with a Session (no need for a web or EJB container!!!)
        //测试session  获取session
        Session session = currentUser.getSession();
        session.setAttribute("name", "火山哥");
        String value = (String) session.getAttribute("name");
        if (value.equals("火山哥")) {
            log.info("================>Retrieved the correct value! [" + value + "]");
        }

        // let's login the current user so we can check against roles and permissions:
        //认证功能 (验证登录)  currentUser.isAuthenticated()此方法来验证是否认证
        if (!currentUser.isAuthenticated()) {
        	//如果没有认证，就将用户名和密码封装为UsernamePasswordToken
        	
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
         
            //记住我
            token.setRememberMe(true);
            try {
            	//执行登录操作
                currentUser.login(token);
                log.info("=================>登录成功");
                
            } catch (UnknownAccountException uae) {
            	//用户名不存在
                log.info("==============》There is no user with username of " + token.getPrincipal());
                log.info("该用户名不存在");
                return;
            } catch (IncorrectCredentialsException ice) {
            	//密码有误
                log.info("===============>Password for account " + token.getPrincipal() + " was incorrect!");
                log.info("密码错误");
                return;
            } catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        //通过Subject.getPrincipal()获取登录的用户名
        log.info("============》User [" + currentUser.getPrincipal() + "] logged in successfully.");

        
        
        //test a role:
        //测试角色Subject.hasRole("roleName")判断用户是否拥有某个角色
        if (currentUser.hasRole("schwartz")) {
            log.info("======================》May the Schwartz be with you!");
        } else {
            log.info("======================》Hello, mere mortal.");
            return;
        }

        //test a typed permission (not instance-level)
        //测试某个角色时候拥有某个权限
        if (currentUser.isPermitted("lightsaber:weild")) {
            log.info("=======================>You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("================>Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        if (currentUser.isPermitted("user:update:employee")) {
            log.info("================>You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("================>Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        //Subject.logout登出
        log.info(""+currentUser.isAuthenticated());
        
        currentUser.logout();
        log.info(""+currentUser.isAuthenticated());
        System.exit(0);
    }
}
