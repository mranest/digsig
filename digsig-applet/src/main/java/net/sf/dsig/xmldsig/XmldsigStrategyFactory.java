package net.sf.dsig.xmldsig;

import net.sf.dsig.Strategy;
import net.sf.dsig.StrategyFactory;

public class XmldsigStrategyFactory implements StrategyFactory {

    @Override
    public String getName() {
        return "xmldsig";
    }

    @Override
    public Strategy getStrategy() {
        return new XmldsigStrategy();
    }

}
